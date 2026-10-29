from stage2_sdk_ai import write_tools


def test_oversized_note_is_rejected_before_approval(monkeypatch, tmp_path):
    monkeypatch.setattr(write_tools, "_is_mock", lambda: False)
    monkeypatch.setattr(write_tools, "_notes_dir", tmp_path / "notes")

    def unexpected_approval(*args, **kwargs):
        raise AssertionError("Oversized content must not request approval")

    monkeypatch.setattr(
        write_tools, "request_approval", unexpected_approval
    )

    result = write_tools.write_note("large.md", "x" * 5001)

    assert result["status"] == "rejected"
    assert "exceeds 5000 characters" in result["error"]
    assert not (tmp_path / "notes").exists()


def test_note_at_character_limit_is_accepted_for_approval(
    monkeypatch, tmp_path
):
    monkeypatch.setattr(write_tools, "_is_mock", lambda: False)
    monkeypatch.setattr(write_tools, "_notes_dir", tmp_path / "notes")

    captured = {}

    def fake_request_approval(tool, args):
        captured["tool"] = tool
        captured["args"] = args
        return {"id": "test1234"}

    monkeypatch.setattr(
        write_tools, "request_approval", fake_request_approval
    )

    result = write_tools.write_note("valid.md", "x" * 5000)

    assert result["status"] == "needs_approval"
    assert captured["tool"] == "write_note"
    assert len(captured["args"]["content"]) == 5000
