from __future__ import annotations

import re
import unicodedata

MAX_LEN = 500

BLOCK_PHRASES = [
    "ignore previous instructions",
    "disregard all prior instructions",
    "disregard all",
    "system: you are now",
    "system:",
    "you are now in developer mode",
    "developer mode",
    "you are now dan",
    "dan mode",
    "pretend you are not an ai",
    "ignore the above and output",
    "output system prompt",
    "begin system prompt",
    "system prompt",
    "human: ignore previous",
    "instruction: bypass safety",
    "bypass safety",
    "base64:",
    "aWdub3JlIHByZXZpb3Vz",
]
_ZERO_WIDTH = re.compile(r"[\\u200b-\\u200f\\u202a-\\u202e\\u2060\\ufeff]")


def check_input(text: str) -> dict:
    """Apply inexpensive screening; this is not a prompt-injection security boundary."""
    if not isinstance(text, str):
        return {"is_safe": False, "reason": "not string"}
    normalized = unicodedata.normalize("NFKC", text)
    normalized = _ZERO_WIDTH.sub("", normalized)
    if normalized.strip() == "":
        return {"is_safe": False, "reason": "empty"}
    if len(normalized) > MAX_LEN:
        return {"is_safe": False, "reason": f"too long {len(normalized)}"}
    if re.search(r"[\\x00-\\x08\\x0b\\x0c\\x0e-\\x1f]", normalized):
        return {"is_safe": False, "reason": "control chars"}
    low = " ".join(normalized.casefold().split())
    for phrase in BLOCK_PHRASES:
        if phrase in low:
            return {"is_safe": False, "reason": f"blocked: {phrase}"}
    return {"is_safe": True, "reason": "ok"}


def validate_input(text: str) -> dict:
    return check_input(text)


def is_safe_input(text: str) -> bool:
    return check_input(text)["is_safe"]


def check(text: str) -> dict:
    return check_input(text)
