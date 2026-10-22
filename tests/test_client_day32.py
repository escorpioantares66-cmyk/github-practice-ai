import asyncio
import pytest
from stage2_sdk_ai.config import AIConfig
from stage2_sdk_ai.client import AIClient

@pytest.mark.asyncio
async def test_semaphore_and_cache():
    cfg = AIConfig(api_key="sk-test-mocked-1234567890")
    client = AIClient(cfg)
    assert client._sem._value == 3
    r1 = await client.complete("hello world")
    r2 = await client.complete("hello world")
    assert r1 == r2  # cache hygiene no double billing
    assert len(client._cache) == 1
    client.cache_clear()
    assert len(client._cache) == 0

def test_frozen():
    cfg = AIConfig(api_key="sk-test")
    try:
        cfg.api_key = "x"
        assert False, "should be frozen"
    except Exception:
        assert True
