from __future__ import annotations

from typing import Any


def check_output(answer: str, sources: list[dict[str, Any]]) -> dict[str, object]:
    if not answer.strip():
        return {"is_safe": False, "confidence": "low", "reason": "empty answer"}
    if not sources:
        return {"is_safe": True, "confidence": "low", "reason": "no sources"}
    src_text = " ".join([s.get("text", "") for s in sources]).lower()
    ans_words = [w for w in answer.lower().split() if len(w) > 4]
    if not ans_words:
        return {"is_safe": True, "confidence": "low", "reason": "short answer"}
    overlap = sum(1 for w in ans_words[:10] if w in src_text)
    if overlap == 0:
        return {"is_safe": True, "confidence": "low", "reason": "no overlap with sources"}
    if overlap < 2:
        return {"is_safe": True, "confidence": "medium", "reason": f"overlap {overlap}"}
    return {"is_safe": True, "confidence": "high", "reason": f"overlap {overlap}"}
