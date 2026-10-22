import pytest

from stage2_sdk_ai.agent import Agent
from stage2_sdk_ai.client import AIClient
from stage2_sdk_ai.config import AIConfig


@pytest.mark.asyncio
async def test_agent_loop_memory_tools():
    cfg = AIConfig(api_key="sk-test-mocked", top_k=2)
    client = AIClient(cfg)
    await client.add_documents(["capital of france is paris", "python tool"])
    agent = Agent(client, max_steps=3)
    agent.register_tool("calc", lambda p: "42")
    agent.register_tool("search", lambda p: "paris")

    out1 = await agent.run("please calc something")
    assert "tool:calc" in out1 or "42" in out1
    assert len(agent.memory.messages) >= 2

    # new agent for second query to avoid calc pollution
    agent2 = Agent(client, max_steps=3)
    agent2.register_tool("search", lambda p: "paris")
    out2 = await agent2.run("what is capital of france?")
    assert "paris" in out2.lower() or "mocked" in out2.lower()
