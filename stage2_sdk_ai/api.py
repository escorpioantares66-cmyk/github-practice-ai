from __future__ import annotations

from typing import Any

try:
    from fastapi import FastAPI

    app = FastAPI(title="RAG Real Phase3 API")
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

    app = FastAPI(title="RAG Real Phase3 API")

from .rag_chain import query_rag
from .vector_store import RealVectorStore

_store: RealVectorStore | None = None

def get_store() -> RealVectorStore:
    global _store
    if _store is None:
        _store = RealVectorStore(persist_path="data/faiss_store")
        _store.load()
    return _store

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "mode": "AI Engineer Mode"}

@app.get("/query")
def query(q: str, top_k: int = 3) -> dict[str, Any]:
    store = get_store()
    return query_rag(q, store, top_k=top_k)
