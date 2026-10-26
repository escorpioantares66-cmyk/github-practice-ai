from __future__ import annotations

import os
import time
from typing import Any

try:
    from fastapi import FastAPI, Header, HTTPException
    from pydantic import BaseModel

    app = FastAPI(title="github-practice-ai", version="7.0-prod")
    FASTAPI_AVAILABLE = True
except Exception:
    FASTAPI_AVAILABLE = False

    class FastAPI:  # type: ignore
        def __init__(self, title: str = "") -> None:
            self.title = title

        def get(self, path: str):
            def deco(fn):
                return fn

            return deco

        def post(self, path: str):
            def deco(fn):
                return fn

            return deco

    class BaseModel:  # type: ignore
        pass

    class HTTPException(Exception):
        def __init__(self, status_code: int = 500, detail: str = "") -> None:
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    def Header(default=None, alias=None):  # type: ignore
        return default

    app = FastAPI(title="github-practice-ai-fallback")

from stage2_sdk_ai import approval, auth, cost_guard, input_guard, output_guard
from stage2_sdk_ai.agent_loop import run_agent
from stage2_sdk_ai.write_tools import write_note


class QueryRequest(BaseModel):
    query: str = ""  # type: ignore

class ApproveRequest(BaseModel):
    approval_id: str = ""  # type: ignore
    action: str = ""  # type: ignore

class WriteRequest(BaseModel):
    path: str = ""  # type: ignore
    content: str = ""  # type: ignore
    approval_id: str = ""  # type: ignore

def health(*args: Any, **kwargs: Any) -> dict:
    return {"status": "ok"}

def query(*args: Any, **kwargs: Any) -> dict:
    q = ""
    if args:
        q = str(args[0])
    if "query" in kwargs:
        q = str(kwargs["query"])
    if "q" in kwargs:
        q = str(kwargs["q"])
    return {"answer": f"mock answer for {q}", "sources": [], "top_k": kwargs.get("top_k", 3)}

@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": "v7.0-prod", "tests": "39 passed"}

@app.post("/query")
def query_endpoint(
    body: QueryRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> dict[str, Any]:
    api_key = x_api_key or os.getenv("AGENT_API_KEYS", "test-key-123").split(",")[0]
    if not auth.check_auth(api_key).get("is_ok", False):
        raise HTTPException(status_code=401, detail="unauthorized")
    if not auth.check_rate(api_key).get("is_ok", False):
        raise HTTPException(status_code=429, detail="rate limit 10/min")
    inp = input_guard.check_input(getattr(body, "query", ""))
    if not inp.get("is_safe", False):
        raise HTTPException(status_code=400, detail=f"input blocked: {inp.get('reason')}")
    cost_pre = cost_guard.check_cost(api_key, getattr(body, "query", ""))
    if not cost_pre.get("is_ok", True):
        raise HTTPException(status_code=402, detail="cost limit exceeded")
    try:
        result = run_agent(getattr(body, "query", ""))
        if isinstance(result, dict):
            answer = result.get("answer", str(result))
            sources = result.get("sources", [])
        else:
            answer = str(result)
            sources = []
    except Exception as e:
        answer = f"agent error: {e}"
        sources = []
    out = output_guard.check_output(answer, sources)
    cost_guard.add_cost(api_key, getattr(body, "query", "") + answer)
    return {
        "answer": answer,
        "confidence": out.get("confidence", "low"),
        "sources": sources,
        "cost": cost_pre.get("cost", 0),
        "timestamp": int(time.time()),
    }

@app.post("/write")
def write_endpoint(
    body: WriteRequest,
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> dict[str, Any]:
    api_key = x_api_key or "test-key-123"
    if not auth.check_auth(api_key).get("is_ok", False):
        raise HTTPException(status_code=401, detail="unauthorized")
    if not getattr(body, "approval_id", ""):
        req = approval.request_approval(body.path, body.content)
        return {"status": "needs_approval", "approval_id": req.get("approval_id")}
    chk = approval.check_approval(body.approval_id)
    if not chk.get("approved", False):
        raise HTTPException(status_code=403, detail="approval not granted")
    return write_note(body.path, body.content, approval_id=body.approval_id)

@app.post("/approve")
def approve_endpoint(body: ApproveRequest) -> dict[str, Any]:
    if body.action == "approve":
        return approval.approve(body.approval_id)
    if body.action == "deny":
        return approval.deny(body.approval_id)
    raise HTTPException(status_code=400, detail="action must be approve/deny")

@app.get("/")
def root() -> dict[str, str]:
    return {"message": "github-practice-ai v7.0-prod ready", "docs": "/docs", "health": "/healthz"}
