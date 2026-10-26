from __future__ import annotations

import re

_BLOCKED = [
    "ignore previous instructions",
    "ignore all instructions",
    "system prompt",
    "you are now",
    "do anything now",
]
_MAX_LEN = 500

def check_input(query: str) -> dict[str, object]:
    q = query.strip()
    if len(q) == 0:
        return {"is_safe": False, "reason": "empty query"}
    if len(q) > _MAX_LEN:
        return {"is_safe": False, "reason": f"too long > {_MAX_LEN}"}
    low = q.lower()
    for phrase in _BLOCKED:
        if phrase in low:
            return {"is_safe": False, "reason": f"blocked phrase: {phrase}"}
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", q):
        return {"is_safe": False, "reason": "control chars"}
    return {"is_safe": True, "reason": "ok"}
