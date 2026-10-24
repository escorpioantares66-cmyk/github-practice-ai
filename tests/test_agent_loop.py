from stage2_sdk_ai.agent_loop import run_agent


def test_agent_loop_mock_two_steps():
    result = run_agent("What is Termux?", max_steps=2)
    assert "query" in result
    assert "steps" in result
    assert len(result["steps"]) == 2
    assert result["steps"][0]["tool"] == "search"
    assert result["is_mock"] is True

def test_agent_loop_mock_final():
    result = run_agent("What is Termux?", max_steps=3)
    assert "answer" in result
    assert "MOCK FINAL" in result["answer"] or "Stopped" in result["answer"]
    assert len(result["steps"]) >= 2
