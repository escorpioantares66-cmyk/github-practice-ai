from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

from .secure_storage import ensure_private_directory, open_private_file
from .vector_store import RealVectorStore

_store: RealVectorStore | None = None
_notes_dir = Path("notes")

def _is_mock() -> bool:
    key = os.getenv("OPENAI_API_KEY", "")
    return key.startswith("sk-test-mocked") or key == ""

def get_store() -> RealVectorStore:
    global _store
    if _store is None:
        _store = RealVectorStore(persist_path="data/faiss_store")
        _store.load()
    return _store

def search(query: str, top_k: int = 3) -> dict[str, Any]:
    if _is_mock():
        return {
            "tool": "search",
            "query": query,
            "results": [
                {"text": f"[MOCK RESULT {i}] for {query}", "score": 0.9 - i * 0.1}
                for i in range(top_k)
            ],
            "is_mock": True,
        }
    store = get_store()
    results = store.similarity_search(query, top_k=top_k)
    return {
        "tool": "search",
        "query": query,
        "results": results,
        "is_mock": False,
    }

def read_note(path: str) -> dict[str, Any]:
    if not isinstance(path, str) or not path.strip():
        return {
            "tool": "read_note",
            "path": "",
            "content": "",
            "error": "invalid note path",
            "is_mock": _is_mock(),
        }

    safe_path = _notes_dir / Path(path).name
    if _is_mock():
        return {
            "tool": "read_note",
            "path": str(safe_path),
            "content": f"[MOCK NOTE] content of {safe_path}",
            "is_mock": True,
        }

    # Verify the directory chain and open the note with O_NOFOLLOW. The
    # bounded read prevents loading an arbitrarily large note into memory.
    ensure_private_directory(_notes_dir)
    try:
        fd = open_private_file(safe_path, os.O_RDONLY)
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            content = handle.read(2001)[:2000]
        return {
            "tool": "read_note",
            "path": str(safe_path),
            "content": content,
            "is_mock": False,
        }
    except FileNotFoundError:
        return {
            "tool": "read_note",
            "path": str(safe_path),
            "content": "",
            "error": "not found",
            "is_mock": False,
        }

TOOL_REGISTRY: dict[str, Callable[..., dict[str, Any]]] = {
    "search": search,
    "read_note": read_note,
}
