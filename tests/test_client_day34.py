import pytest

from stage2_sdk_ai.client import AIClient
from stage2_sdk_ai.config import AIConfig


@pytest.mark.asyncio
async def test_rag_and_tools():
    cfg = AIConfig(api_key="sk-test-mocked", top_k=2)
    client = AIClient(cfg)
    await client.add_documents(["python is great", "rust is fast", "ai is future"])
    res = await client.similarity_search("python")
    assert len(res) == 2
    assert any("python" in r for r in res)
    rag = await client.rag_complete("what is great?")
    assert "mocked" in rag
    client.register_tool("calc", lambda p: "42")
    out = await client.complete_with_tools("please calc this")
    assert "tool:calc:42" in out
