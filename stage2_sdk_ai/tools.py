from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, Callable

from .secure_storage import ensure_private_directory, open_private_file
from .vector_store import MAX_QUERY_CHARS, RealVectorStore

_store: RealVectorStore | None = None
_notes_dir = Path("notes")
MAX_SEARCH_TOP_K = 50


def _is_mock() -> bool:
    flag = os.getenv("STAGE2_SDK_AI_MOCK_MODE", "").strip().lower()
    key = os.getenv("OPENAI_API_KEY", "")
    return flag in {"1", "true", "yes"} or key.startswith("sk-test-mocked")


def _requester_notes_dir(requester: str | None) -> Path:
    """Return an isolated note directory; never fall back to shared storage."""
    if not isinstance(requester, str) or not requester.strip():
        raise ValueError("A valid requester identity is required")
    identity_hash = hashlib.sha256(requester.encode("utf-8")).hexdigest()
    return _notes_dir / identity_hash


def _validate_search(query: str, top_k: int) -> None:
    if not isinstance(query, str) or not query.strip():
        raise ValueError("query must be non-empty text")
    if len(query) > MAX_QUERY_CHARS:
        raise ValueError(f"query exceeds {MAX_QUERY_CHARS} characters")
    if isinstance(top_k, bool) or not isinstance(top_k, int):
        raise ValueError("top_k must be an integer")
    if not 1 <= top_k <= MAX_SEARCH_TOP_K:
        raise ValueError(f"top_k must be between 1 and {MAX_SEARCH_TOP_K}")


def get_store() -> RealVectorStore:
    global _store
    if _store is None:
        store_path = Path("data/faiss_store")
        candidate = RealVectorStore(persist_path=str(store_path))
        loaded = candidate.load()
        store_file = store_path / "store.json"
        if not loaded and (store_file.exists() or store_file.is_symlink()):
            raise RuntimeError("Persisted vector store failed validation")
        _store = candidate
    return _store


def search(query: str, top_k: int = 3) -> dict[str, Any]:
    _validate_search(query, top_k)
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
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError(
            "OPENAI_API_KEY is required; mock results require explicit mock mode"
        )
    store = get_store()
    results = store.similarity_search(query, top_k=top_k)
    return {
        "tool": "search",
        "query": query,
        "results": results,
        "is_mock": False,
    }


def read_note(path: str, requester: str | None = None) -> dict[str, Any]:
    if not isinstance(path, str) or not path.strip() or len(path) > 255:
        return {
            "tool": "read_note",
            "path": "",
            "content": "",
            "error": "invalid note path",
            "is_mock": _is_mock(),
        }

    # Notes are addressed by filename only. API calls always supply the
    # authenticated requester identity; model-supplied paths cannot select
    # another requester's directory.
    filename = Path(path).name
    if filename in {"", ".", ".."}:
        return {
            "tool": "read_note",
            "path": "",
            "content": "",
            "error": "invalid note path",
            "is_mock": _is_mock(),
        }
    try:
        note_dir = _requester_notes_dir(requester)
    except ValueError:
        return {
            "tool": "read_note",
            "path": "",
            "content": "",
            "error": "A valid requester identity is required",
            "is_mock": _is_mock(),
        }
    safe_path = note_dir / filename
    if _is_mock():
        return {
            "tool": "read_note",
            "path": str(safe_path),
            "content": f"[MOCK NOTE] content of {safe_path}",
            "is_mock": True,
        }

    ensure_private_directory(note_dir)
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
