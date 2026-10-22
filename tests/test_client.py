import pytest

from stage2_sdk_ai.client import ResilientAIClient
from stage2_sdk_ai.config import AIConfig


@pytest.mark.asyncio
async def test_config_frozen():
    cfg = AIConfig(api_key="sk-test-12345678")
    with pytest.raises(AttributeError):
        cfg.model = "gpt-4"  # type: ignore


@pytest.mark.asyncio
async def test_masked_key():
    cfg = AIConfig(api_key="sk-1234567890abcdef")
    assert "..." in cfg.masked_key()


@pytest.mark.asyncio
async def test_cache_hygiene_no_double_billing():
    cfg = AIConfig(api_key="sk-test-mocked", cache_ttl_seconds=60)
    client = ResilientAIClient(cfg)
    emb1 = await client.embed("hello world")
    emb2 = await client.embed("hello world")
    assert emb1 == emb2
    await client.aclose()


@pytest.mark.asyncio
async def test_semaphore_exists():
    cfg = AIConfig(api_key="sk-test-mocked", concurrency=3)
    client = ResilientAIClient(cfg)
    assert client._sem._value == 3
    await client.aclose()
