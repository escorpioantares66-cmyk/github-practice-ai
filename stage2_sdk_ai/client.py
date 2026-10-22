import asyncio
import logging
import time
from dataclasses import dataclass

import httpx

from .config import AIConfig

logger = logging.getLogger("gh-ai")

try:
    from github_practice import APIError, TTLCache
except ImportError:

    class APIError(Exception):
        pass

    class TTLCache(dict):
        def __init__(self, ttl):
            self.ttl = ttl


@dataclass
class CostTracker:
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    trace_id: str = ""


class ResilientAIClient:
    def __init__(self, config: AIConfig):
        self.config = config
        self._sem = asyncio.Semaphore(config.concurrency)
        self._cache = {}
        self._client = httpx.AsyncClient(timeout=config.timeout)
        self.cost = CostTracker(trace_id=f"trace-{int(time.time())}")

    async def _request_with_retry(self, fn, *args, **kwargs):
        last_exc = None
        for attempt in range(1, self.config.max_retries + 1):
            try:
                async with self._sem:
                    logger.info(
                        f"[{self.cost.trace_id}] attempt={attempt} model={self.config.model}"
                    )
                    return await fn(*args, **kwargs)
            except Exception as e:
                last_exc = e
                wait = 2**attempt * 0.2
                logger.warning(f"[{self.cost.trace_id}] retry {attempt} after {wait}s: {e}")
                await asyncio.sleep(wait)
        raise APIError(f"Failed after {self.config.max_retries} retries: {last_exc}")

    async def embed(self, text: str):
        cache_key = f"emb:{hash(text)}"
        if cache_key in self._cache:
            logger.info(f"[{self.cost.trace_id}] cache_hit {cache_key}")
            return self._cache[cache_key]
        result = [0.0] * 1536
        self._cache[cache_key] = result
        return result

    async def aclose(self):
        await self._client.aclose()
