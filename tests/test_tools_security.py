import pytest

from stage2_sdk_ai import tools


def test_search_requires_explicit_mock_mode_when_api_key_missing(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("STAGE2_SDK_AI_MOCK_MODE", "0")
    monkeypatch.setattr(
        tools,
        "get_store",
        lambda: (_ for _ in ()).throw(AssertionError("store should not be opened")),
    )
    with pytest.raises(RuntimeError, match="mock results require explicit mock mode"):
        tools.search("query")


def test_search_mock_mode_is_explicit(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("STAGE2_SDK_AI_MOCK_MODE", "1")
    result = tools.search("test query", top_k=2)
    assert result["is_mock"] is True
    assert len(result["results"]) == 2


@pytest.mark.parametrize(
    ("query", "top_k"),
    [
        ("", 3),
        ("   ", 3),
        ("query", 0),
        ("query", 51),
        ("query", True),
        ("x" * 10_001, 3),
        (None, 3),
    ],
)
def test_search_rejects_invalid_or_unbounded_arguments(monkeypatch, query, top_k):
    monkeypatch.setenv("STAGE2_SDK_AI_MOCK_MODE", "1")
    with pytest.raises(ValueError):
        tools.search(query, top_k=top_k)


def test_missing_api_key_does_not_enable_mock_mode(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("STAGE2_SDK_AI_MOCK_MODE", raising=False)
    assert tools._is_mock() is False
