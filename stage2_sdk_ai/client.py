from __future__ import annotations
import asyncio
import time
from typing import Dict
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
        self._sem = asyncio.Semaphore(3)
        self._cache: TTLCache = TTLCache(maxsize=100, ttl=300)
        self._client = AsyncOpenAI(api_key=config.api_key) if HAS_OPENAI else None
        self._hits: Dict[str, float] = {}

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

    def cache_clear(self):
        self._cache.clear()
