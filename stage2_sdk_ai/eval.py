from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class EvalResult:
    prompt: str
    output: str
    latency_ms: float
    passed: bool

class EvalHarness:
    def __init__(self, client):
        self.client = client

    async def eval_case(self, prompt: str, expect_contains: str = "mocked") -> EvalResult:
        t0 = time.time()
        out = await self.client.complete(prompt)
        dt = (time.time() - t0) * 1000
        passed = expect_contains.lower() in out.lower()
        return EvalResult(prompt, out, dt, passed)

    async def run_suite(self, cases: list[tuple[str, str]]) -> dict:
        results = []
        for prompt, expect in cases:
            r = await self.eval_case(prompt, expect)
            results.append(r)
        total = len(results)
        ok = sum(1 for r in results if r.passed)
        avg = sum(r.latency_ms for r in results) / total if total else 0
        return {"total": total, "passed": ok, "avg_ms": avg, "results": results}
