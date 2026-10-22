import pytest

from stage2_sdk_ai.client import AIClient
from stage2_sdk_ai.config import AIConfig
from stage2_sdk_ai.eval import EvalHarness
from stage2_sdk_ai.orchestrator import Orchestrator
from stage2_sdk_ai.tracing import Tracer


@pytest.mark.asyncio
async def test_orchestrator_tracing_eval():
    cfg = AIConfig(api_key="sk-test-mocked", top_k=2)
    client = AIClient(cfg)
    await client.add_documents(["tracing test doc", "eval doc"])
    tracer = Tracer()
    orch = Orchestrator(client, tracer)
    out = await orch.run("test orchestrator")
    assert "mocked" in out.lower()
    assert len(tracer.spans) >= 2
    assert "rag_search" in tracer.summary()

    harness = EvalHarness(client)
    suite = await harness.run_suite([("hello", "mocked"), ("hi", "mocked")])
    assert suite["total"] == 2
    assert suite["passed"] >= 1
