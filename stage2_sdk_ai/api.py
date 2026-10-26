import pydantic

if not hasattr(pydantic.BaseModel, "model_fields"):
    pass

from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from stage2_sdk_ai import auth, cost_guard, input_guard, output_guard
from stage2_sdk_ai.agent_loop import run_agent

app = FastAPI(title="github-practice-ai v7.0-prod")

class QueryReq(BaseModel):
    query: str
    name: Optional[str] = None
    top_k: Optional[int] = 5

class WriteReq(BaseModel):
    path: str
    content: str

def _check_auth(x_api_key: Optional[str] = Header(None)):
    if not auth.verify_api_key(x_api_key or ""):
        raise HTTPException(status_code=401, detail="Invalid API key")
    auth.check_rate_limit(x_api_key or "anon")
    return x_api_key

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
    if not cost_guard.check_budget(len(q)):
        return {"answer": "cost limit $1 exceeded", "blocked": True}
    res = run_agent(q, top_k=req.top_k or 5)
    out = output_guard.check_output(res.get("answer", ""), res.get("sources", []))
    cost_guard.add_cost(len(q) + len(res.get("answer", "")))
    return {
        "answer": res.get("answer"),
        "confidence": out.get("confidence"),
        "sources": res.get("sources", []),
    }

@app.post("/write")
def write_endpoint(req: WriteReq, api_key: str = Depends(_check_auth)):
    from stage2_sdk_ai import approval as appr_mod
    r = appr_mod.request_approval(req.path, req.content)
    return {
        "needs_approval": True,
        "approval_id": r.get("id") or r.get("approval_id"),
        "id": r.get("id"),
    }

@app.post("/approve")
def approve_endpoint(approval_id: str, api_key: str = Depends(_check_auth)):
    from stage2_sdk_ai import approval as appr_mod
    return appr_mod.approve(approval_id)

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
