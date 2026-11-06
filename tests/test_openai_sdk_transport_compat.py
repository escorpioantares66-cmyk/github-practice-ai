"""Runtime tests for the current OpenAI SDK + HTTPX2 transport stack.

These tests use real OpenAI SDK clients with an in-process HTTPX2 MockTransport.
No API key, external network request, or billable API call is made.
The regular project CI may skip this module when its legacy dependency set has
not installed HTTPX2; the dedicated sdk-transport-compat job installs the
candidate stack and runs the complete module.
"""
from __future__ import annotations

import json
import warnings

import pytest

httpx2 = pytest.importorskip(
    "httpx2",
    reason="candidate HTTPX2 stack is installed in its dedicated CI job",
)

from openai import AsyncOpenAI, OpenAI  # noqa: E402

from stage2_sdk_ai import client as client_module  # noqa: E402
from stage2_sdk_ai import rag_chain, vector_store  # noqa: E402
from stage2_sdk_ai.client import AIClient  # noqa: E402
from stage2_sdk_ai.config import AIConfig  # noqa: E402

BASE_URL = "https://api.openai-transport.test/v1"
API_KEY = "sk-transport-compatibility"
CREATED = 1_700_000_000
EMBEDDING = [0.001] * 1536


def _completion_payload(content: str = "sdk-transport-ok") -> dict:
    return {
        "id": "chatcmpl_transport_test",
        "object": "chat.completion",
        "created": CREATED,
        "model": "gpt-4o-mini",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
    }


def _embedding_payload() -> dict:
    return {
        "object": "list",
        "data": [{"object": "embedding", "index": 0, "embedding": EMBEDDING}],
        "model": "text-embedding-3-small",
        "usage": {"prompt_tokens": 2, "total_tokens": 2},
    }


def _stream_payload() -> bytes:
    events = [
        {
            "id": "chatcmpl_stream_test",
            "object": "chat.completion.chunk",
            "created": CREATED,
            "model": "gpt-4o-mini",
            "choices": [
                {
                    "index": 0,
                    "delta": {"role": "assistant", "content": "sdk-stream-ok"},
                    "finish_reason": None,
                }
            ],
        },
        {
            "id": "chatcmpl_stream_test",
            "object": "chat.completion.chunk",
            "created": CREATED,
            "model": "gpt-4o-mini",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        },
    ]
    lines = [f"data: {json.dumps(event)}\n\n" for event in events]
    lines.append("data: [DONE]\n\n")
    return "".join(lines).encode("utf-8")


def _transport_handler(request: httpx2.Request, seen: list[dict]):
    assert request.headers.get("authorization") == f"Bearer {API_KEY}"
    path = request.url.path
    body = json.loads(request.content.decode("utf-8")) if request.content else {}
    seen.append({"method": request.method, "path": path, "body": body})

    if request.method != "POST":
        return httpx2.Response(405, request=request)
    if path == "/v1/chat/completions":
        if body.get("stream") is True:
            return httpx2.Response(
                200,
                request=request,
                headers={"content-type": "text/event-stream"},
                content=_stream_payload(),
            )
        return httpx2.Response(200, request=request, json=_completion_payload())
    if path == "/v1/embeddings":
        return httpx2.Response(200, request=request, json=_embedding_payload())
    return httpx2.Response(404, request=request, json={"error": "unexpected path"})


def test_default_sync_client_constructs_with_sdk_managed_httpx2() -> None:
    with OpenAI(api_key=API_KEY, timeout=5.0) as client:
        assert isinstance(client, OpenAI)


@pytest.mark.asyncio
async def test_default_async_client_constructs_with_sdk_managed_httpx2() -> None:
    async with AsyncOpenAI(api_key=API_KEY, timeout=5.0) as client:
        assert isinstance(client, AsyncOpenAI)


def test_sync_chat_streaming_and_embeddings_reach_expected_paths() -> None:
    seen: list[dict] = []
    http_client = httpx2.Client(
        transport=httpx2.MockTransport(lambda request: _transport_handler(request, seen))
    )
    client = OpenAI(api_key=API_KEY, base_url=BASE_URL, http_client=http_client)
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "sync chat"}],
        )
        assert response.choices[0].message.content == "sdk-transport-ok"

        chunks = list(
            client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": "sync stream"}],
                stream=True,
            )
        )
        assert "".join(chunk.choices[0].delta.content or "" for chunk in chunks) == "sdk-stream-ok"

        embedding = client.embeddings.create(
            model="text-embedding-3-small",
            input="sync embedding",
        )
        assert embedding.data[0].embedding == EMBEDDING
    finally:
        client.close()

    assert [(item["method"], item["path"]) for item in seen] == [
        ("POST", "/v1/chat/completions"),
        ("POST", "/v1/chat/completions"),
        ("POST", "/v1/embeddings"),
    ]
    assert seen[1]["body"]["stream"] is True


@pytest.mark.asyncio
async def test_async_chat_and_streaming_reach_expected_paths() -> None:
    seen: list[dict] = []
    http_client = httpx2.AsyncClient(
        transport=httpx2.MockTransport(lambda request: _transport_handler(request, seen))
    )
    async with AsyncOpenAI(api_key=API_KEY, base_url=BASE_URL, http_client=http_client) as client:
        response = await client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "async chat"}],
        )
        assert response.choices[0].message.content == "sdk-transport-ok"

        stream = await client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "async stream"}],
            stream=True,
        )
        parts = [chunk.choices[0].delta.content or "" async for chunk in stream]
        assert "".join(parts) == "sdk-stream-ok"

    assert [(item["method"], item["path"]) for item in seen] == [
        ("POST", "/v1/chat/completions"),
        ("POST", "/v1/chat/completions"),
    ]
    assert seen[1]["body"]["stream"] is True


def test_application_sync_wrappers_use_real_sdk_chat_and_embedding_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import openai

    monkeypatch.setenv("OPENAI_API_KEY", API_KEY)
    monkeypatch.delenv("STAGE2_SDK_AI_MOCK_MODE", raising=False)
    seen: list[dict] = []
    created_clients: list[OpenAI] = []
    sdk_openai = openai.OpenAI

    def client_factory(*, api_key: str) -> OpenAI:
        http_client = httpx2.Client(
            transport=httpx2.MockTransport(
                lambda request: _transport_handler(request, seen)
            )
        )
        client = sdk_openai(api_key=api_key, base_url=BASE_URL, http_client=http_client)
        created_clients.append(client)
        return client

    monkeypatch.setattr(openai, "OpenAI", client_factory)
    try:
        answer, is_mock = rag_chain._get_llm_answer("check the sync wrapper")
        assert answer == "sdk-transport-ok"
        assert is_mock is False

        embedding, dimension, is_mock = vector_store._get_query_embedding(
            "check the embedding wrapper"
        )
        values = embedding.tolist() if hasattr(embedding, "tolist") else list(embedding)
        assert dimension == 1536
        assert len(values) == 1536
        assert is_mock is False
    finally:
        for client in created_clients:
            client.close()

    assert [item["path"] for item in seen] == [
        "/v1/chat/completions",
        "/v1/embeddings",
    ]


@pytest.mark.asyncio
async def test_application_async_client_uses_real_sdk_chat_and_stream_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from openai import AsyncOpenAI as SDKAsyncOpenAI

    monkeypatch.setenv("CI", "false")
    seen: list[dict] = []

    def async_client_factory(*, api_key: str) -> AsyncOpenAI:
        http_client = httpx2.AsyncClient(
            transport=httpx2.MockTransport(
                lambda request: _transport_handler(request, seen)
            )
        )
        return SDKAsyncOpenAI(
            api_key=api_key,
            base_url=BASE_URL,
            http_client=http_client,
        )

    monkeypatch.setattr(client_module, "AsyncOpenAI", async_client_factory)
    monkeypatch.setattr(client_module, "HAS_OPENAI", True)
    client = AIClient(AIConfig(api_key=API_KEY, max_retries=1))
    try:
        assert client._client is not None
        answer = await client.complete("check the async application wrapper")
        assert answer == "sdk-transport-ok"

        chunks = [
            chunk
            async for chunk in client.stream("check the async streaming wrapper")
        ]
        assert "".join(chunks) == "sdk-stream-ok"
    finally:
        await client.aclose()

    assert [item["path"] for item in seen] == [
        "/v1/chat/completions",
        "/v1/chat/completions",
    ]
    assert seen[1]["body"]["stream"] is True


def test_starlette_testclient_runs_without_legacy_httpx_deprecation() -> None:
    pytest.importorskip("starlette")
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route
    from starlette.testclient import TestClient

    def endpoint(request):
        return PlainTextResponse("testclient-ok")

    app = Starlette(routes=[Route("/", endpoint)])
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        with TestClient(app) as client:
            response = client.get("/")
        assert response.status_code == 200
        assert response.text == "testclient-ok"

    legacy_httpx_warnings = [
        warning
        for warning in captured
        if "httpx" in str(warning.message).lower()
        and "deprecated" in str(warning.message).lower()
    ]
    assert not legacy_httpx_warnings


def test_sync_responses_websocket_manager_builds_expected_endpoint() -> None:
    """Build the Responses WebSocket URL without opening a network connection."""
    with OpenAI(api_key=API_KEY, base_url=BASE_URL) as client:
        manager = client.responses.connect(
            extra_query={"trace_id": "responses-ws-test"},
            extra_headers={"X-Transport-Test": "responses"},
        )
        assert str(manager._prepare_url()) == "wss://api.openai-transport.test/v1/responses"


@pytest.mark.asyncio
async def test_async_responses_websocket_manager_builds_expected_endpoint() -> None:
    """The async Responses client must use the same WebSocket endpoint contract."""
    async with AsyncOpenAI(api_key=API_KEY, base_url=BASE_URL) as client:
        manager = client.responses.connect(
            extra_query={"trace_id": "responses-ws-async-test"},
            extra_headers={"X-Transport-Test": "responses-async"},
        )
        assert str(manager._prepare_url()) == "wss://api.openai-transport.test/v1/responses"


def test_sync_beta_realtime_manager_builds_expected_endpoint() -> None:
    """The retained beta Realtime API must target its WebSocket resource path."""
    with OpenAI(api_key=API_KEY, base_url=BASE_URL) as client:
        manager = client.beta.realtime.connect(
            model="gpt-realtime",
            extra_query={"trace_id": "realtime-ws-test"},
            extra_headers={"X-Transport-Test": "realtime"},
        )
        assert str(manager._prepare_url()) == "wss://api.openai-transport.test/v1/realtime"


@pytest.mark.asyncio
async def test_async_beta_realtime_manager_builds_expected_endpoint() -> None:
    """The async retained beta Realtime API must preserve the WebSocket path."""
    async with AsyncOpenAI(api_key=API_KEY, base_url=BASE_URL) as client:
        manager = client.beta.realtime.connect(
            model="gpt-realtime",
            extra_query={"trace_id": "realtime-ws-async-test"},
            extra_headers={"X-Transport-Test": "realtime-async"},
        )
        assert str(manager._prepare_url()) == "wss://api.openai-transport.test/v1/realtime"


def test_beta_realtime_provider_identity_requires_caller_owned_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Provider identities cannot silently fall back to SDK-managed WebSocket auth."""
    from types import SimpleNamespace

    from openai import OpenAIError
    from openai.lib import _client_auth

    monkeypatch.setattr(
        _client_auth._sdk_client,
        "is_x509_workload_identity",
        lambda identity: False,
    )
    client = SimpleNamespace(
        workload_identity=object(),
        _provider_runtime=None,
        default_headers={},
    )

    with pytest.raises(OpenAIError, match="not supported by WebSocket connections"):
        _client_auth._validate_beta_realtime_auth(client, {})

    _client_auth._validate_beta_realtime_auth(
        client,
        {"Authorization": "Bearer caller-managed-test-token"},
    )


def test_beta_realtime_x509_identity_is_rejected_even_with_explicit_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """X.509 workload identity remains unsupported for the retained beta WebSocket."""
    from types import SimpleNamespace

    from openai import OpenAIError
    from openai.lib import _client_auth

    monkeypatch.setattr(
        _client_auth._sdk_client,
        "is_x509_workload_identity",
        lambda identity: True,
    )
    client = SimpleNamespace(
        workload_identity=object(),
        _provider_runtime=None,
        default_headers={"Authorization": "Bearer caller-managed-test-token"},
    )

    with pytest.raises(OpenAIError, match="not supported by WebSocket connections"):
        _client_auth._validate_beta_realtime_auth(
            client,
            {"Authorization": "Bearer caller-managed-test-token"},
        )


def test_agent_loop_uses_real_sdk_and_closes_client(monkeypatch: pytest.MonkeyPatch) -> None:
    import openai

    from stage2_sdk_ai import agent_loop

    monkeypatch.setenv("OPENAI_API_KEY", API_KEY)
    monkeypatch.delenv("STAGE2_SDK_AI_MOCK_MODE", raising=False)
    seen: list[dict] = []
    clients: list[OpenAI] = []
    sdk_openai = openai.OpenAI

    def factory(*, api_key: str) -> OpenAI:
        def handler(request: httpx2.Request):
            body = json.loads(request.content.decode("utf-8"))
            seen.append({"method": request.method, "path": request.url.path, "body": body})
            return httpx2.Response(
                200,
                request=request,
                json=_completion_payload(
                    '{"tool":"final","args":{"answer":"sdk-agent-ok"}}'
                ),
            )

        http_client = httpx2.Client(transport=httpx2.MockTransport(handler))
        client = sdk_openai(api_key=api_key, base_url=BASE_URL, http_client=http_client)
        clients.append(client)
        return client

    monkeypatch.setattr(openai, "OpenAI", factory)
    monkeypatch.setattr(agent_loop.cost_guard, "record_model_usage", lambda *a, **k: None)
    monkeypatch.setattr(agent_loop.cost_guard, "MODEL_NAME", "gpt-4o-mini")
    monkeypatch.setattr(agent_loop.cost_guard, "MAX_PROMPT_TOKENS_PER_CALL", 100)
    monkeypatch.setattr(agent_loop.cost_guard, "MAX_COMPLETION_TOKENS_PER_CALL", 100)
    result = agent_loop._real_llm_pick_tool("sdk integration", [], requester="sdk-user")
    assert result == {"tool": "final", "args": {"answer": "sdk-agent-ok"}}
    assert seen[0]["path"] == "/v1/chat/completions"
    assert clients and all(client._client.is_closed for client in clients)


def test_rag_and_embedding_wrappers_close_sync_sdk_clients(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import openai

    monkeypatch.setenv("OPENAI_API_KEY", API_KEY)
    monkeypatch.delenv("STAGE2_SDK_AI_MOCK_MODE", raising=False)
    seen: list[dict] = []
    clients: list[OpenAI] = []
    sdk_openai = openai.OpenAI

    def factory(*, api_key: str) -> OpenAI:
        http_client = httpx2.Client(
            transport=httpx2.MockTransport(lambda request: _transport_handler(request, seen))
        )
        client = sdk_openai(api_key=api_key, base_url=BASE_URL, http_client=http_client)
        clients.append(client)
        return client

    monkeypatch.setattr(openai, "OpenAI", factory)
    assert rag_chain._get_llm_answer("lifecycle test")[1] is False
    assert vector_store._get_query_embedding("lifecycle test")[2] is False
    assert len(clients) == 2
    assert all(client._client.is_closed for client in clients)


@pytest.mark.asyncio
async def test_async_client_propagates_exhausted_provider_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenCompletions:
        async def create(self, **kwargs):
            raise RuntimeError("provider unavailable")

    class BrokenClient:
        def __init__(self, **kwargs):
            self.chat = type("Chat", (), {"completions": BrokenCompletions()})()

        async def close(self):
            return None

    monkeypatch.setattr(client_module, "AsyncOpenAI", BrokenClient)
    monkeypatch.setattr(client_module, "HAS_OPENAI", True)
    monkeypatch.setenv("CI", "false")
    instance = AIClient(AIConfig(api_key=API_KEY, max_retries=1))
    try:
        with pytest.raises(RuntimeError, match="provider unavailable"):
            await instance.complete("must not become a mock answer")
        with pytest.raises(RuntimeError, match="provider unavailable"):
            await instance.chat([{"role": "user", "content": "must not become a mock"}])
    finally:
        await instance.aclose()


def test_query_api_runs_agent_through_real_sdk_mock_transport(
    monkeypatch: pytest.MonkeyPatch, tmp_path,
) -> None:
    import openai
    from fastapi.testclient import TestClient

    from stage2_sdk_ai import agent_loop, auth, cost_guard, quota_store
    from stage2_sdk_ai.api import app

    monkeypatch.setenv("OPENAI_API_KEY", API_KEY)
    monkeypatch.setenv("AGENT_QUOTA_DB_PATH", str(tmp_path / "api-quota.sqlite3"))
    monkeypatch.setenv("CI", "false")
    monkeypatch.delenv("STAGE2_SDK_AI_MOCK_MODE", raising=False)
    monkeypatch.setattr(agent_loop, "_is_mock", lambda: False)
    monkeypatch.setattr(auth, "verify_api_key", lambda key: key == "api-test-key")
    monkeypatch.setattr(auth, "check_requester_rate_limit", lambda key: True)
    monkeypatch.setattr(auth, "requester_identity", lambda key: "api-requester")

    seen: list[dict] = []
    sdk_openai = openai.OpenAI

    def factory(*, api_key: str) -> OpenAI:
        def handler(request: httpx2.Request):
            assert request.headers.get("authorization") == f"Bearer {API_KEY}"
            body = json.loads(request.content.decode("utf-8"))
            seen.append({"path": request.url.path, "body": body})
            return httpx2.Response(
                200,
                request=request,
                json=_completion_payload(
                    '{"tool":"final","args":{"answer":"api-sdk-integration-ok"}}'
                ),
            )

        transport = httpx2.MockTransport(handler)
        return sdk_openai(api_key=api_key, base_url=BASE_URL,
                          http_client=httpx2.Client(transport=transport))

    monkeypatch.setattr(openai, "OpenAI", factory)
    with TestClient(app) as test_client:
        response = test_client.post(
            "/query",
            headers={"X-API-Key": "api-test-key"},
            json={"query": "integration test", "top_k": 2},
        )

    assert response.status_code == 200, response.text
    assert response.json()["answer"] == "api-sdk-integration-ok"
    assert [item["path"] for item in seen] == ["/v1/chat/completions"]
    usage = quota_store.get_daily_usage("api-requester", cost_guard._utc_day())
    assert usage["input_tokens"] == 2
    assert usage["output_tokens"] == 3
