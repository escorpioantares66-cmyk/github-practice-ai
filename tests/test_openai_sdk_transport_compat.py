"""Runtime tests for the current OpenAI SDK + HTTPX2 transport stack.

These tests use real OpenAI SDK clients with an in-process HTTPX2 MockTransport.
No API key, external network request, or billable API call is made.
The regular project CI may skip this module when its legacy dependency set has
not installed HTTPX2; the dedicated sdk-transport-compat job installs the
candidate stack and runs the complete module.
"""
from __future__ import annotations

import asyncio
import json
import warnings

import pytest

httpx2 = pytest.importorskip("httpx2", reason="candidate HTTPX2 stack is installed in its dedicated CI job")

from openai import AsyncOpenAI, OpenAI  # noqa: E402

from stage2_sdk_ai import client as client_module  # noqa: E402
from stage2_sdk_ai import rag_chain, vector_store  # noqa: E402
from stage2_sdk_ai.config import AIConfig  # noqa: E402
from stage2_sdk_ai.client import AIClient  # noqa: E402

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
