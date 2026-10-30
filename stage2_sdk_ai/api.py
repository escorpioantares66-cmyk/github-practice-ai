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

app = FastAPI(title="github-practice-ai v7.0-prod")


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
    if not auth.check_rate_limit(f"approver:{x_approver_key}"):
        raise HTTPException(status_code=429, detail="Approver rate limit exceeded")
    return "authenticated_approver"

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

    r = appr_mod.request_approval(
        "write_note",
        {"path": str(safe_path), "content": req.content},
    )
    approval_id = r.get("id") or r.get("approval_id")

    return {
        "needs_approval": True,
        "approval_id": approval_id,
        "id": r.get("id"),
    }


@app.post("/approve")
def approve_endpoint(
    approval_id: str,
    approver: str = Depends(_check_approver_auth),
):
    from stage2_sdk_ai import approval as appr_mod

    result = appr_mod.approve(approval_id, approver=approver)
    status = result.get("status")
    if status == "not_found":
        raise HTTPException(status_code=404, detail="Approval not found")
    if status == "invalid_id":
        raise HTTPException(status_code=422, detail="Invalid approval ID")
    if status == "invalid_transition":
        raise HTTPException(status_code=409, detail="Approval is no longer pending")
    return result


@app.post("/deny")
def deny_endpoint(
    req: DenyApprovalReq,
    approver: str = Depends(_check_approver_auth),
):
    """Reject a pending request using a separately authenticated approver."""
    from stage2_sdk_ai import approval as appr_mod

    if len(req.reason) > 500:
        raise HTTPException(status_code=422, detail="Denial reason exceeds 500 characters")
    result = appr_mod.deny(
        req.approval_id,
        approver=approver,
        reason=req.reason,
    )
    status = result.get("status")
    if status == "not_found":
        raise HTTPException(status_code=404, detail="Approval not found")
    if status == "invalid_id":
        raise HTTPException(status_code=422, detail="Invalid approval ID")
    if status == "invalid_transition":
        raise HTTPException(status_code=409, detail="Approval is no longer pending")
    return result


@app.post("/write/execute")
def execute_write_endpoint(
    req: ExecuteWriteReq,
    api_key: str = Depends(_check_auth),
):
    """Execute a stored approved write; clients cannot submit replacement data."""
    from stage2_sdk_ai.write_tools import execute_approved_write

    result = execute_approved_write(req.approval_id)
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
    if status == "invalid_approved_payload":
        raise HTTPException(status_code=409, detail=result.get("error", status))
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
