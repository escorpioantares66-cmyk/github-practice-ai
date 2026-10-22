from __future__ import annotations

from .tracing import Tracer


class Orchestrator:
    def __init__(self, client, tracer: Tracer | None = None):
        self.client = client
        self.tracer = tracer or Tracer()

    async def run(self, prompt: str) -> str:
        with self.tracer.span("rag_search"):
            ctx = []
            if hasattr(self.client, "_store") and self.client._store:
                ctx = await self.client.similarity_search(prompt, k=2)

        with self.tracer.span("llm_complete", prompt=prompt[:40]):
            if ctx:
                p = f"Context: {' | '.join(ctx)}\nQ: {prompt}"
            else:
                p = prompt
            out = await self.client.complete(p)

        with self.tracer.span("finalize"):
            final = f"{out} | trace:{self.tracer.summary()[:120]}"
        return final
