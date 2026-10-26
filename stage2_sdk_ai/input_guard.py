from __future__ import annotations

import re

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

def check_input(text: str) -> dict:
    if not isinstance(text, str):
        return {"is_safe": False, "reason": "not string"}
    if text.strip() == "":
        return {"is_safe": False, "reason": "empty"}
    if len(text) > MAX_LEN:
        return {"is_safe": False, "reason": f"too long {len(text)}"}
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", text):
        return {"is_safe": False, "reason": "control chars"}
    low = text.lower()
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
