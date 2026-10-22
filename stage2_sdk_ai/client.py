from __future__ import annotations

import asyncio

from cachetools import TTLCache

from .config import AIConfig

try:
    from openai import AsyncOpenAI

    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

class AIClient:
    def __init__(self, config: AIConfig):
        self.config = config
        self._sem = asyncio.Semaphore(config.concurrency)
        self._cache: TTLCache = TTLCache(maxsize=100, ttl=config.cache_ttl_seconds)
        self._client = AsyncOpenAI(api_key=config.api_key) if HAS_OPENAI else None

    async def complete(self, prompt: str, retries: int = 3) -> str:
        if prompt in self._cache:
            return self._cache[prompt]
        async with self._sem:
            for i in range(retries):
                try:
                    if self._client:
                        r = await self._client.chat.completions.create(
                            model="gpt-4o-mini",
                            messages=[{"role": "user", "content": prompt}],
                        )
                        out = r.choices[0].message.content
                    else:
                        out = f"mocked:{prompt[:20]}"
                    self._cache[prompt] = out
                    return out
                except Exception:
                    if i == retries - 1:
                        raise
                    await asyncio.sleep(2**i * 0.5)
            return ""

    async def embed(self, text: str) -> list[float]:
        key = f"embed:{text}"
        if key in self._cache:
            return self._cache[key]
        async with self._sem:
            vec = [0.1, 0.2, 0.3]  # mocked vector hygiene
            self._cache[key] = vec
            return vec

    async def aclose(self):
        if self._client:
            try:
                await self._client.close()
            except Exception:
                pass
        self._cache.clear()

    def cache_clear(self):
        self._cache.clear()

ResilientAIClient = AIClient
