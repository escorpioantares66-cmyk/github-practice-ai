from __future__ import annotations

import asyncio
import math
from typing import AsyncGenerator, Callable

from cachetools import TTLCache

from .config import AIConfig

try:
    from openai import AsyncOpenAI

    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False

def _mock_embed(text: str) -> list[float]:
    return [float(len(text) % 10) / 10, float(len(set(text)) % 10) / 10, 0.3]

def _cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0

class AIClient:
    def __init__(self, config: AIConfig):
        self.config = config
        self._sem = asyncio.Semaphore(config.concurrency)
        self._cache: TTLCache = TTLCache(maxsize=500, ttl=config.cache_ttl_seconds)
        self._client = AsyncOpenAI(api_key=config.api_key) if HAS_OPENAI else None
        self._store: list[dict] = []
        self._tools: dict[str, Callable] = {}

    async def _retry_sleep(self, attempt: int) -> None:
        await asyncio.sleep(min(2**attempt * 0.5, 5))

    async def complete(self, prompt: str) -> str:
        if prompt in self._cache:
            return self._cache[prompt]
        async with self._sem:
            for i in range(self.config.max_retries):
                try:
                    if not self._client:
                        out = f"mocked:{prompt[:20]}"
                    else:
                        r = await self._client.chat.completions.create(
                            model="gpt-4o-mini",
                            messages=[{"role": "user", "content": prompt}],
                        )
                        out = r.choices[0].message.content
                    self._cache[prompt] = out
                    return out
                except Exception:
                    if i == self.config.max_retries - 1:
                        raise
                    await self._retry_sleep(i)
            return ""

    async def chat(self, messages: list[dict]) -> str:
        key = f"chat:{str(messages)}"
        if key in self._cache:
            return self._cache[key]
        async with self._sem:
            for i in range(self.config.max_retries):
                try:
                    if not self._client:
                        out = f"mocked-chat:{messages[-1]['content'][:20]}"
                    else:
                        r = await self._client.chat.completions.create(
                            model="gpt-4o-mini", messages=messages
                        )
                        out = r.choices[0].message.content
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
            vec = _mock_embed(text)
            self._cache[key] = vec
            return vec

    async def add_documents(self, docs: list[str]) -> None:
        for d in docs:
            e = await self.embed(d)
            self._store.append({"text": d, "embedding": e})

    async def similarity_search(self, query: str, k: int | None = None) -> list[str]:
        k = k or self.config.top_k
        qe = await self.embed(query)
        scored = sorted(
            self._store,
            key=lambda x: _cosine(qe, x["embedding"]),
            reverse=True,
        )
        return [x["text"] for x in scored[:k]]

    async def rag_complete(self, query: str) -> str:
        ctx = await self.similarity_search(query)
        prompt = f"Context: {' | '.join(ctx)}\n\nQuestion: {query}"
        return await self.complete(prompt)

    def register_tool(self, name: str, func: Callable) -> None:
        self._tools[name] = func

    async def complete_with_tools(self, prompt: str) -> str:
        for name, fn in self._tools.items():
            if name in prompt.lower():
                try:
                    res = fn(prompt)
                    return f"tool:{name}:{res}"
                except Exception as e:
                    return f"tool:{name}:error:{e}"
        return await self.complete(prompt)

    async def aclose(self) -> None:
        if self._client:
            try:
                await self._client.close()
            except Exception:
                pass
        self._cache.clear()

    def cache_clear(self) -> None:
        self._cache.clear()

ResilientAIClient = AIClient
