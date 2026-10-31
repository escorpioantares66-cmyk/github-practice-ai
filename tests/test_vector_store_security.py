import json
import stat

import pytest

from stage2_sdk_ai import vector_store
from stage2_sdk_ai.vector_store import RealVectorStore, _chunk_text


def test_chunking_rejects_non_progressing_and_invalid_parameters():
    with pytest.raises(ValueError):
        _chunk_text("some text", chunk_size=10, overlap=10)
    with pytest.raises(ValueError):
        _chunk_text("some text", chunk_size=0, overlap=0)
    with pytest.raises(ValueError):
        _chunk_text("some text", chunk_size=10, overlap=-1)
    with pytest.raises(ValueError):
        _chunk_text("some text", chunk_size=10, overlap=11)


def test_chunking_rejects_non_integer_parameters():
    with pytest.raises(ValueError):
        _chunk_text("some text", chunk_size=True, overlap=0)


def test_embedding_requires_explicit_mock_mode(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("STAGE2_SDK_AI_MOCK_MODE", "0")
    with pytest.raises(RuntimeError, match="OPENAI_API_KEY is required"):
        vector_store._get_query_embedding("query")


def test_explicit_mock_mode_works_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("STAGE2_SDK_AI_MOCK_MODE", "1")
    embedding, dimension, is_mock = vector_store._get_query_embedding("query")
    assert dimension == vector_store.EMBEDDING_DIM
    assert is_mock is True
    assert len(embedding) == vector_store.EMBEDDING_DIM


def test_add_documents_does_not_partially_mutate_on_embedding_failure(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-mocked")
    store = RealVectorStore()
    calls = 0
    original = vector_store._get_query_embedding

    def fail_second(text):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("simulated embedding failure")
        return original(text)

    monkeypatch.setattr(vector_store, "_get_query_embedding", fail_second)
    with pytest.raises(RuntimeError, match="simulated embedding failure"):
        store.add_documents(
            [{"text": "abcdefghijklmnopqrst", "metadata": {}}],
            chunk_size=10,
            overlap=0,
        )
    assert store.texts == []
    assert store.metadatas == []
    assert store.embeddings == []


def test_save_uses_private_file_permissions(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-mocked")
    store = RealVectorStore(persist_path=str(tmp_path / "private-store"))
    store.add_documents([{"text": "private", "metadata": {}}])
    store.save()
    mode = stat.S_IMODE((tmp_path / "private-store" / "store.json").stat().st_mode)
    assert mode == 0o600


def test_save_replaces_symlink_without_modifying_target(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-mocked")
    directory = tmp_path / "store"
    directory.mkdir()
    target = tmp_path / "outside.json"
    target.write_text('{"outside":"unchanged"}', encoding="utf-8")
    destination = directory / "store.json"
    destination.symlink_to(target)

    RealVectorStore(persist_path=str(directory)).save()

    assert target.read_text(encoding="utf-8") == '{"outside":"unchanged"}'
    assert destination.is_symlink() is False
    assert json.loads(destination.read_text(encoding="utf-8"))["texts"] == []


def test_load_rejects_symlinked_store_file(tmp_path):
    directory = tmp_path / "store"
    directory.mkdir()
    target = tmp_path / "outside.json"
    target.write_text(
        json.dumps(
            {"texts": [], "metadatas": [], "embeddings": [], "embedding_dim": 1536}
        ),
        encoding="utf-8",
    )
    (directory / "store.json").symlink_to(target)

    assert RealVectorStore(persist_path=str(directory)).load() is False


def test_load_rejects_inconsistent_store_arrays(tmp_path):
    directory = tmp_path / "store"
    directory.mkdir()
    (directory / "store.json").write_text(
        json.dumps(
            {
                "texts": ["one"],
                "metadatas": [],
                "embeddings": [],
                "embedding_dim": 1536,
            }
        ),
        encoding="utf-8",
    )
    store = RealVectorStore(persist_path=str(directory))
    assert store.load() is False
    assert store.texts == []
    assert store.metadatas == []
    assert store.embeddings == []


def test_load_rejects_non_finite_embedding_values(tmp_path):
    directory = tmp_path / "store"
    directory.mkdir()
    (directory / "store.json").write_text(
        json.dumps(
            {
                "texts": ["one"],
                "metadatas": [{}],
                "embeddings": [[float("nan")] * 1536],
                "embedding_dim": 1536,
            }
        ),
        encoding="utf-8",
    )
    assert RealVectorStore(persist_path=str(directory)).load() is False


def test_similarity_search_rejects_unbounded_parameters(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-mocked")
    store = RealVectorStore()
    store.add_documents([{"text": "one", "metadata": {}}])
    with pytest.raises(ValueError):
        store.similarity_search("query", top_k=vector_store.MAX_TOP_K + 1)
    with pytest.raises(ValueError):
        store.similarity_search("query", top_k=True)
    with pytest.raises(ValueError):
        store.similarity_search("x" * (vector_store.MAX_QUERY_CHARS + 1))
