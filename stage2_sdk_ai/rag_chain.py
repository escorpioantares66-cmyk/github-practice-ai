from __future__ import annotations

import os
from typing import Any

from .vector_store import RealVectorStore


def _get_llm_answer(prompt: str) -> tuple[str, bool]:
    key = os.getenv("OPENAI_API_KEY", "")
    if key.startswith("sk-test-mocked") or key == "":
        return f"[MOCK ANSWER] for: {prompt[:80]}", True
    try:
        from openai import OpenAI  # type: ignore

        client = OpenAI(api_key=key)
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=200,
        )
        return resp.choices[0].message.content or "", False
    except Exception:
        return f"[MOCK FALLBACK] for: {prompt[:80]}", True

def query_rag(
    query: str, store: RealVectorStore, top_k: int = 3
) -> dict[str, Any]:
    results = store.similarity_search(query, top_k=top_k)
    context = "\n".join([r["text"] for r in results])
    prompt = f"Context:\n{context}\n\nQuestion: {query}\nAnswer with sources."
    answer, is_mock = _get_llm_answer(prompt)
    return {
        "query": query,
        "answer": answer,
        "sources": results,
        "is_mock": is_mock,
        "top_k": top_k,
    }
