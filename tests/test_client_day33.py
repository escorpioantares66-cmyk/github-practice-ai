
import pytest

from stage2_sdk_ai.client import AIClient
from stage2_sdk_ai.config import AIConfig


@pytest.mark.asyncio
async def test_chat_and_stream():
    cfg = AIConfig(api_key="sk-test-mocked")
    client = AIClient(cfg)
    chat_out = await client.chat([{"role": "user", "content": "hi"}])
    assert "mocked" in chat_out

    chunks = []
    async for c in client.stream("hello stream"):
        chunks.append(c)
    assert len(chunks) > 0
    assert "".join(chunks).startswith("mocked-stream")

@pytest.mark.asyncio
async def test_retry_config():
    cfg = AIConfig(api_key="sk-test", max_retries=5)
    assert cfg.max_retries == 5
    assert cfg.concurrency == 3
