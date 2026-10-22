from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Callable

from .tracing import Tracer


@dataclass
class SwarmResult:
    agent_id: str
    output: str
    status: str = "ok"

class SwarmAgent:
    def __init__(self, agent_id: str, client, tools: dict[str, Callable] | None = None):
        self.agent_id = agent_id
        self.client = client
        self.tools = tools or {}

    async def run(self, prompt: str) -> SwarmResult:
        try:
            for n, f in self.tools.items():
                self.client.register_tool(n, f)
            out = await self.client.complete(prompt)
            return SwarmResult(self.agent_id, out, "ok")
        except Exception as e:
            return SwarmResult(self.agent_id, str(e), f"error:{e}")

class Swarm:
    def __init__(self, clients: list, tracer: Tracer | None = None):
        self.clients = clients
        self.tracer = tracer or Tracer()
        self.agents = [SwarmAgent(f"agent-{i}", c) for i, c in enumerate(clients)]

    async def run_parallel(self, prompts: list[str]) -> list[SwarmResult]:
        with self.tracer.span("swarm_parallel", n=len(prompts)):
            tasks = []
            for i, prompt in enumerate(prompts):
                ag = self.agents[i % len(self.agents)]
                tasks.append(ag.run(prompt))
            results = await asyncio.gather(*tasks)
            return list(results)

    async def run_consensus(self, prompt: str, n: int = 3) -> str:
        with self.tracer.span("swarm_consensus", n=n):
            prompts = [f"{prompt} [variant {i}]" for i in range(n)]
            results = await self.run_parallel(prompts)
            ok = [r for r in results if r.status == "ok"]
            if not ok:
                return "no consensus"
            combined = " | ".join([r.output[:120] for r in ok])
            return f"consensus({len(ok)}/{n}): {combined}"

class ParallelOrchestrator:
    def __init__(self, client, max_concurrency: int = 3):
        self.client = client
        self.sem = asyncio.Semaphore(max_concurrency)
        self.tracer = Tracer()

    async def _guarded_complete(self, prompt: str) -> str:
        async with self.sem:
            with self.tracer.span("parallel_complete"):
                low = prompt.lower()
                if not prompt.strip() or "ignore previous" in low:
                    return "guarded: blocked"
                out = await self.client.complete(prompt)
                if len(out) > 2000:
                    out = out[:2000]
                return out

    async def run_batch(self, prompts: list[str]) -> list[str]:
        with self.tracer.span("parallel_batch", total=len(prompts)):
            tasks = [self._guarded_complete(p) for p in prompts]
            return list(await asyncio.gather(*tasks))

class GuardedEval:
    def __init__(self, client):
        self.client = client

    async def evaluate(self, prompt: str, expect: str = "mocked") -> dict:
        guards = {
            "empty": not prompt.strip(),
            "too_long": len(prompt) > 5000,
            "injection": "ignore previous" in prompt.lower(),
        }
        if any(guards.values()):
            return {
                "prompt": prompt,
                "passed": False,
                "guarded": True,
                "guards": guards,
            }

        out = await self.client.complete(prompt)
        passed = expect.lower() in out.lower() and len(out) < 5000
        return {
            "prompt": prompt,
            "output": out[:200],
            "passed": passed,
            "guarded": False,
            "guards": guards,
        }
