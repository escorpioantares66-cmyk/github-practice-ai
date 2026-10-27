import os

os.environ.setdefault("OPENAI_API_KEY", "sk-test-mocked")

from stage2_sdk_ai.agent_loop import _collect_sources


def test_collect_sources_from_search_results():
    history = [
        {
            "step": 0,
            "tool": "search",
            "args": {"query": "laundry"},
            "result": {
                "tool": "search",
                "results": [{"text": "match one", "score": 0.9}],
            },
        }
    ]
    sources = _collect_sources(history)
    assert sources == [{"text": "match one", "score": 0.9}]


def test_collect_sources_from_read_note():
    history = [
        {
            "step": 0,
            "tool": "read_note",
            "args": {"path": "notes/x.md"},
            "result": {"path": "notes/x.md", "content": "note body"},
        }
    ]
    sources = _collect_sources(history)
    assert sources == [{"path": "notes/x.md", "text": "note body"}]


def test_collect_sources_skips_unknown_tool():
    history = [{"step": 0, "tool": "other", "args": {}, "result": {}}]
    assert _collect_sources(history) == []


def test_collect_sources_handles_missing_result():
    history = [{"step": 0, "tool": "search", "args": {}}]
    assert _collect_sources(history) == []
