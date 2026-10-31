from __future__ import annotations

import re
from typing import Any

_EMAIL = re.compile(
    r"(?i)\b[A-Z0-9.!#$%&'*+/=?^_{|}~-]+@"
    r"[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+\b"
)
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
_PHONE = re.compile(r"(?<!\w)(?:\+?\d{1,3}[ .()-]?)?(?:\(?\d{2,4}\)?[ .()-]?)\d{2,4}[ .()-]?\d{3,4}(?!\w)")
_STREET_ADDRESS = re.compile(
    r"\b\d{1,6}\s+[A-Za-z0-9.'-]+(?:\s+[A-Za-z0-9.'-]+){0,3}\s+"
    r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b\.?",
    re.IGNORECASE,
)


def _luhn_valid(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def contains_pii(text: str) -> bool:
    """Return whether text still contains one of the supported PII patterns."""
    if not isinstance(text, str):
        return False
    if _EMAIL.search(text) or _SSN.search(text) or _PHONE.search(text):
        return True
    if any(_luhn_valid(match.group(0)) for match in _CARD.finditer(text)):
        return True
    return bool(_STREET_ADDRESS.search(text))


def redact_pii(text: str) -> tuple[str, bool]:
    """Redact common high-confidence PII patterns without discarding other text."""
    if not isinstance(text, str):
        return "", True

    redacted = _EMAIL.sub("[REDACTED:EMAIL]", text)
    redacted = _SSN.sub("[REDACTED:SSN]", redacted)

    def replace_card(match: re.Match[str]) -> str:
        return "[REDACTED:CARD]" if _luhn_valid(match.group(0)) else match.group(0)

    redacted = _CARD.sub(replace_card, redacted)
    redacted = _PHONE.sub("[REDACTED:PHONE]", redacted)
    redacted = _STREET_ADDRESS.sub("[REDACTED:ADDRESS]", redacted)
    return redacted, redacted != text


def _extract_text(item: Any) -> str:
    if isinstance(item, dict):
        value = item.get("text", "")
        return value if isinstance(value, str) else str(value)
    return item if isinstance(item, str) else str(item)


def _sanitize_value(value: Any) -> tuple[Any, bool]:
    if isinstance(value, str):
        return redact_pii(value)
    if isinstance(value, list):
        output = []
        changed = False
        for item in value:
            safe_item, item_changed = _sanitize_value(item)
            output.append(safe_item)
            changed = changed or item_changed
        return output, changed
    if isinstance(value, dict):
        output = {}
        changed = False
        for key, item in value.items():
            safe_item, item_changed = _sanitize_value(item)
            output[key] = safe_item
            changed = changed or item_changed
        return output, changed
    return value, False


def check_output(text: str, sources: list | None = None) -> dict:
    if not isinstance(text, str):
        return {
            "filtered": True,
            "confidence": "low",
            "reason": "not string",
            "text": "",
            "sources": [],
        }

    safe_text, answer_changed = redact_pii(text)
    safe_sources, sources_changed = _sanitize_value(sources or [])
    source_texts = [_extract_text(source) for source in (sources or [])]
    low_text = safe_text.lower()
    t_words = set(low_text.split())
    max_common = 0
    for source_text in source_texts:
        safe_source, _ = redact_pii(source_text)
        source_low = safe_source.lower()
        if source_low in low_text or low_text in source_low:
            max_common = max(max_common, 5)
        common = len(t_words & set(source_low.split()))
        max_common = max(max_common, common)

    if max_common >= 4:
        confidence = "high"
    elif max_common >= 1:
        confidence = "medium"
    else:
        confidence = "low"

    filtered = answer_changed or sources_changed
    return {
        "filtered": filtered,
        "confidence": confidence,
        "text": safe_text,
        "sources": safe_sources,
    }


def validate_output(text: str, sources=None) -> dict:
    return check_output(text, sources)


def filter_output(text: str, sources=None) -> dict:
    return check_output(text, sources)


def check(text: str, sources=None) -> dict:
    return check_output(text, sources)
