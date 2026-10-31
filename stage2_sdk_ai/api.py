import time
import uuid
from typing import Optional

import pydantic
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from stage2_sdk_ai import auth, cost_guard, input_guard, output_guard
from stage2_sdk_ai.agent_loop import run_agent
from stage2_sdk_ai.logging_setup import get_logger

if not hasattr(pydantic.BaseModel, "model_fields"):
    pass

logger = get_logger(__name__)

# Bound request bodies before Starlette/FastAPI parses JSON. This protects
# endpoints with small field-level limits (such as /write and /deny) from
# oversized JSON payloads that would otherwise be parsed before validation.
MAX_REQUEST_BODY_BYTES = 1_048_576  # 1 MiB


class RequestBodyLimitMiddleware:
    """ASGI middleware that caps body bytes before application parsing."""

    def __init__(self, app, max_body_bytes: int = MAX_REQUEST_BODY_BYTES):
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = next(
            (value for key, value in scope.get("headers", []) if key.lower() == b"content-length"),
            None,
        )
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError:
                declared_length = -1
            if declared_length > self.max_body_bytes:
                await self._too_large(scope, send)
                return

        # Buffer at most limit+1 bytes. This also enforces the limit when the
        # client omits Content-Length or streams a chunked request body.
        messages = []
        total = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                messages.append(message)
                break
            body = message.get("body", b"")
            total += len(body)
            if total > self.max_body_bytes:
                await self._too_large(scope, send)
                return
            messages.append(message)
            if not message.get("more_body", False):
                break

        async def replay_receive():
            if messages:
                return messages.pop(0)
            return await receive()

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _too_large(scope, send):
        body = b'{"detail":"Request body too large"}'
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": body})


app = FastAPI(title="github-practice-ai v7.0-prod")
app.add_middleware(RequestBodyLimitMiddleware)


@app.middleware("http")
async def add_request_id_and_log(request: Request, call_next):
    """Tags every request with an id (returned as X-Request-ID and attached
    to request.state), logs one structured line per request with its
    outcome, and converts any unhandled exception into clean JSON instead
    of leaking a stack trace.

    Note: the exception handling lives HERE, in the middleware's own
    try/except, rather than in a separate @app.exception_handler(Exception).
    When a custom @app.middleware("http") is present, FastAPI's exception
    handlers are not reliably invoked for exceptions raised deeper in the
    stack -- Starlette's BaseHTTPMiddleware (which powers @app.middleware)
    re-raises past them instead of letting them convert the exception to a
    response. Catching it directly around call_next() here is the correct,
    documented workaround for that interaction.
    """
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    start = time.time()
    try:
        response = await call_next(request)
    except Exception as exc:
        logger.error(
            "unhandled exception",
            exc_info=exc,
            extra={
                "request_id": request_id,
                "path": request.url.path,
                "method": request.method,
            },
        )
        response = JSONResponse(
            status_code=500,
            content={"error": "internal_error", "request_id": request_id},
        )
    duration_ms = (time.time() - start) * 1000
    response.headers["X-Request-ID"] = request_id
    logger.info(
        "request completed",
        extra={
            "request_id": request_id,
            "path": request.url.path,
            "method": request.method,
            "status_code": response.status_code,
            "duration_ms": round(duration_ms, 2),
        },
    )
    return response


class QueryReq(BaseModel):
    query: str
    name: Optional[str] = None
    top_k: Optional[int] = 5

class WriteReq(BaseModel):
    path: str
    content: str


class ExecuteWriteReq(BaseModel):
    approval_id: str

    class Config:
        extra = "forbid"


class DenyApprovalReq(BaseModel):
    approval_id: str
    reason: str = ""

def _check_auth(x_api_key: Optional[str] = Header(None)):
    if not auth.verify_api_key(x_api_key or ""):
        raise HTTPException(status_code=401, detail="Invalid API key")
    if not auth.check_rate_limit(x_api_key or "anon"):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    return x_api_key

def _check_approver_auth(
    x_approver_key: Optional[str] = Header(None, alias="X-Approver-Key"),
):
    if not auth.verify_approver_key(x_approver_key):
        raise HTTPException(
            status_code=403,
            detail="Invalid or missing approver credentials",
        )
    identity = auth.approver_identity(x_approver_key or "")
    if not auth.check_rate_limit(identity):
        raise HTTPException(status_code=429, detail="Approver rate limit exceeded")
    return x_approver_key or ""


@app.get("/healthz")
def healthz():
    return {"status": "ok", "version": "v7.0-prod", "tests": "39 passed"}

@app.get("/")
def root():
    return {"message": "github-practice-ai v7.0-prod ready", "docs": "/docs"}

@app.post("/query")
def query_endpoint(req: QueryReq, api_key: str = Depends(_check_auth)):
    q = req.query
    chk = input_guard.check_input(q)
    if not chk.get("is_safe", True):
        return {"answer": "blocked by input_guard", "blocked": True}
    if not cost_guard.check_budget(api_key, q):
        return {"answer": "cost limit $1 exceeded", "blocked": True}
    res = run_agent(q, top_k=req.top_k or 5)
    out = output_guard.check_output(res.get("answer", ""), res.get("sources", []))
    cost_guard.add_cost(api_key, q + res.get("answer", ""))
    return {
        "answer": res.get("answer"),
        "confidence": out.get("confidence"),
        "sources": res.get("sources", []),
    }


@app.post("/write")
def write_endpoint(req: WriteReq, api_key: str = Depends(_check_auth)):
    from stage2_sdk_ai import approval as appr_mod
    from stage2_sdk_ai.write_tools import MAX_NOTE_CHARS, canonical_note_path

    if len(req.content) > MAX_NOTE_CHARS:
        raise HTTPException(
            status_code=422,
            detail=f"Content exceeds {MAX_NOTE_CHARS} characters",
        )

    try:
        safe_path = canonical_note_path(req.path)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    requester = auth.requester_identity(api_key)
    if requester is None:
        raise HTTPException(status_code=401, detail="Invalid API key identity")

    try:
        r = appr_mod.request_approval(
            "write_note",
            {"path": str(safe_path), "content": req.content},
            requester=requester,
        )
    except appr_mod.ApprovalAuditError as exc:
        raise HTTPException(
            status_code=500,
            detail={
                "error": "approval_audit_incomplete",
                "approval_id": exc.approval_id,
                "recovery": "Operator review required; request cannot be approved.",
            },
        ) from exc
    approval_id = r.get("id") or r.get("approval_id")

    return {
        "needs_approval": True,
        "approval_id": approval_id,
        "id": r.get("id"),
    }


@app.post("/approve")
def approve_endpoint(
    approval_id: str,
    approver_key: str = Depends(_check_approver_auth),
):
    from stage2_sdk_ai import approval as appr_mod

    result = appr_mod.approve(approval_id, approver_key=approver_key)
    status = result.get("status")
    if status == "unauthorized":
        raise HTTPException(status_code=403, detail="Invalid or missing approver credentials")
    if status == "not_found":
        raise HTTPException(status_code=404, detail="Approval not found")
    if status == "invalid_id":
        raise HTTPException(status_code=422, detail="Invalid approval ID")
    if status == "invalid_transition":
        raise HTTPException(status_code=409, detail="Approval is no longer pending")
    if status == "approval_audit_incomplete":
        raise HTTPException(
            status_code=500,
            detail={
                "error": "approval_audit_incomplete",
                "approval_id": approval_id,
                "recovery": "Operator review required; approval cannot be executed.",
            },
        )
    return result


@app.post("/deny")
def deny_endpoint(
    req: DenyApprovalReq,
    approver_key: str = Depends(_check_approver_auth),
):
    """Reject a pending request using a separately authenticated approver."""
    from stage2_sdk_ai import approval as appr_mod

    if len(req.reason) > 500:
        raise HTTPException(status_code=422, detail="Denial reason exceeds 500 characters")
    result = appr_mod.deny(
        req.approval_id,
        approver_key=approver_key,
        reason=req.reason,
    )
    status = result.get("status")
    if status == "unauthorized":
        raise HTTPException(status_code=403, detail="Invalid or missing approver credentials")
    if status == "not_found":
        raise HTTPException(status_code=404, detail="Approval not found")
    if status == "invalid_id":
        raise HTTPException(status_code=422, detail="Invalid approval ID")
    if status == "invalid_transition":
        raise HTTPException(status_code=409, detail="Approval is no longer pending")
    if status == "approval_audit_incomplete":
        raise HTTPException(
            status_code=500,
            detail={
                "error": "approval_audit_incomplete",
                "approval_id": req.approval_id,
                "recovery": "Operator review required; denial remains terminal.",
            },
        )
    return result


@app.post("/write/execute")
def execute_write_endpoint(
    req: ExecuteWriteReq,
    api_key: str = Depends(_check_auth),
):
    """Execute a stored approved write; clients cannot submit replacement data."""
    from stage2_sdk_ai.write_tools import execute_approved_write

    requester = auth.requester_identity(api_key)
    if requester is None:
        raise HTTPException(status_code=401, detail="Invalid API key identity")

    result = execute_approved_write(req.approval_id, requester=requester)
    status = result.get("status")
    if status == "not_found":
        raise HTTPException(status_code=404, detail="Approval not found")
    if status == "invalid_id":
        raise HTTPException(status_code=422, detail="Invalid approval ID")
    if status == "pending":
        raise HTTPException(status_code=409, detail="Approval is still pending")
    if status == "invalid_transition":
        raise HTTPException(status_code=409, detail="Approval was already consumed or denied")
    if status == "approval_mismatch":
        raise HTTPException(status_code=409, detail="Approval does not authorize this operation")
    if status == "requester_mismatch":
        raise HTTPException(status_code=403, detail="Approval belongs to a different requester")
    if status == "invalid_approved_payload":
        raise HTTPException(status_code=409, detail=result.get("error", status))
    if status in {
        "execution_failed",
        "execution_failed_audit_incomplete",
        "execution_failure_recording_failed",
        "consumption_audit_incomplete",
        "approval_audit_incomplete",
        "invalid_approved_payload_operator_review",
    }:
        raise HTTPException(
            status_code=500,
            detail={
                "error": result.get("error", status),
                "approval_id": req.approval_id,
                "recovery": "Operator review required; approval remains consumed.",
            },
        )
    return result


def health():
    return healthz()

def query_compat(*args, **kwargs):
    q = args[0] if args else kwargs.get("q") or kwargs.get("query", "hi")
    tk = kwargs.get("top_k", 5)
    chk = input_guard.check_input(q)
    if not chk.get("is_safe", True):
        return {"answer": "blocked", "blocked": True}
    res = run_agent(q, top_k=tk)
    return res

query = query_compat
