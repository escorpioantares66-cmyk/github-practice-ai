from __future__ import annotations

import asyncio
from typing import AsyncGenerator

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
        self._cache: TTLCache = TTLCache(maxsize=200, ttl=config.cache_ttl_seconds)
        self._client = AsyncOpenAI(api_key=config.api_key) if HAS_OPENAI else None

    async def _retry_sleep(self, attempt: int):
        await asyncio.sleep(min(2**attempt * 0.5, 5))

    async def complete(self, prompt: str) -> str:
        if prompt in self._cache:
            return self._cache[prompt]
        async with self._sem:
            for i in range(self.config.max_retries):
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
                except Exception as e:
                    if "429" in str(e) or "500" in str(e) or i < self.config.max_retries - 1:
                        if i == self.config.max_retries - 1:
                            raise
                        await self._retry_sleep(i)
                        continue
                    raise
            return ""

    async def chat(self, messages: list[dict]) -> str:
        key = f"chat:{str(messages)}"
        if key in self._cache:
            return self._cache[key]
        async with self._sem:
            for i in range(self.config.max_retries):
                try:
                    if self._client:
                        r = await self._client.chat.completions.create(
                            model="gpt-4o-mini", messages=messages
                        )
                        out = r.choices[0].message.content
                    else:
                        out = f"mocked-chat:{messages[-1]['content'][:20]}"
                    self._cache[key] = out
                    return out
                except Exception:
                    if i == self.config.max_retries - 1:
                        raise
                    await self._retry_sleep(i)
            return ""

    async def stream(self, prompt: str) -> AsyncGenerator[str, None]:
        async with self._sem:
            if self._client:
                s = await self._client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": prompt}],
                    stream=True,
                )
                async for chunk in s:
                    if chunk.choices[0].delta.content:
                        yield chunk.choices[0].delta.content
            else:
                for ch in f"mocked-stream:{prompt[:20]}".split():
                    yield ch + " "
                    await asyncio.sleep(0.01)

    async def embed(self, text: str) -> list[float]:
        key = f"embed:{text}"
        if key in self._cache:
            return self._cache[key]
        async with self._sem:
            vec = [0.1, 0.2, 0.3]
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
