from __future__ import annotations


def _extract_text(item) -> str:
    if isinstance(item, dict):
        return item.get("text", "")
    return str(item)

def check_output(text: str, sources: list | None = None) -> dict:
    if not isinstance(text, str):
        return {"filtered": True, "confidence": "low", "reason": "not string"}
    if not sources:
        return {"filtered": False, "confidence": "low", "text": text}
    texts = [_extract_text(s) for s in sources]
    low_text = text.lower()
    t_words = set(low_text.split())
    max_common = 0
    for s in texts:
        s_low = s.lower()
        if s_low in low_text or low_text in s_low:
            max_common = max(max_common, 5)
        common = len(t_words & set(s_low.split()))
        max_common = max(max_common, common)
    if max_common >= 4:
        conf = "high"
    elif max_common >= 1:
        conf = "medium"
    else:
        conf = "low"
    filtered = False
    if "@" in text and ".com" in low_text:
        filtered = True
        conf = "low"
    if "123-45-6789" in text or "4111" in text:
        filtered = True
        conf = "low"
    return {"filtered": filtered, "confidence": conf, "text": text}

def validate_output(text: str, sources=None) -> dict:
    return check_output(text, sources)

def filter_output(text: str, sources=None) -> dict:
    return check_output(text, sources)

def check(text: str, sources=None) -> dict:
    return check_output(text, sources)
