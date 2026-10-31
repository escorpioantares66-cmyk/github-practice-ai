"""Coverage tests for stage2_sdk_ai/vector_store.py mock-mode paths.

These target branches that don't require faiss/numpy to be installed:
chunking edge cases, metadata normalization in add_documents, the
empty-store and filter/hybrid paths in similarity_search, and a full
save()/load() JSON round trip.
"""
import os

os.environ.setdefault("OPENAI_API_KEY", "sk-test-mocked")

from stage2_sdk_ai.vector_store import RealVectorStore, _chunk_text


def test_chunk_text_empty_returns_empty_list():
    assert _chunk_text("") == []


def test_chunk_text_rejects_non_string_input():
    import pytest

    with pytest.raises(TypeError, match="text must be a string"):
        _chunk_text(None)


def test_chunk_text_shorter_than_chunk_size_single_chunk():
    chunks = _chunk_text("hello world", chunk_size=500, overlap=50)
    assert chunks == ["hello world"]


def test_chunk_text_multiple_chunks_with_overlap():
    text = "a" * 120
    chunks = _chunk_text(text, chunk_size=50, overlap=10)
    assert len(chunks) > 1
    assert all(len(c) <= 50 for c in chunks)
    # reconstructs original content when overlaps stripped (sanity on logic)
    assert "".join(chunks)[:50] == text[:50]


def test_add_documents_metadata_from_list_of_dicts():
    store = RealVectorStore(persist_path=".test_rag_cov_list")
    store.add_documents([{"text": "doc one", "metadata": [{"source": "a"}, {"source": "b"}]}])
    assert store.metadatas[0] == {"source": "a"}


def test_add_documents_metadata_from_dict():
    store = RealVectorStore(persist_path=".test_rag_cov_dict")
    store.add_documents([{"text": "doc two", "metadata": {"source": "x"}}])
    assert store.metadatas[0] == {"source": "x"}


def test_add_documents_metadata_missing_defaults_empty_dict():
    store = RealVectorStore(persist_path=".test_rag_cov_none")
    store.add_documents([{"text": "doc three"}])
    assert store.metadatas[0] == {}


def test_add_documents_empty_text_falls_back_to_raw_text_chunk():
    store = RealVectorStore(persist_path=".test_rag_cov_emptytext")
    store.add_documents([{"text": "", "metadata": {}}])
    # _chunk_text("") -> [] -> falls back to chunks = [raw_text] == [""]
    assert store.texts == [""]


def test_similarity_search_empty_store_returns_empty_list():
    store = RealVectorStore(persist_path=".test_rag_cov_search_empty")
    assert store.similarity_search("anything") == []


def test_similarity_search_filter_meta_excludes_non_matching():
    store = RealVectorStore(persist_path=".test_rag_cov_filter")
    store.add_documents(
        [
            {"text": "kenya laundry service", "metadata": {"lang": "en"}},
            {"text": "servicio de lavanderia", "metadata": {"lang": "es"}},
        ]
    )
    results = store.similarity_search("laundry", top_k=5, filter_meta={"lang": "en"})
    assert all(r["metadata"]["lang"] == "en" for r in results)
    assert len(results) == 1


def test_similarity_search_hybrid_boosts_term_match():
    store = RealVectorStore(persist_path=".test_rag_cov_hybrid")
    store.add_documents(
        [
            {"text": "nairobi laundry pickup", "metadata": {}},
            {"text": "completely unrelated text about weather", "metadata": {}},
        ]
    )
    results = store.similarity_search("laundry", top_k=2, hybrid=True)
    assert results[0]["text"] == "nairobi laundry pickup"


def test_save_and_load_round_trip(tmp_path):
    persist_path = str(tmp_path / "vecstore")
    store = RealVectorStore(persist_path=persist_path)
    store.add_documents([{"text": "roundtrip doc", "metadata": {"k": "v"}}])
    store.save()

    reloaded = RealVectorStore(persist_path=persist_path)
    ok = reloaded.load()
    assert ok is True
    assert reloaded.texts == store.texts
    assert reloaded.metadatas == store.metadatas


def test_load_returns_false_when_no_store_file(tmp_path):
    store = RealVectorStore(persist_path=str(tmp_path / "does_not_exist"))
    assert store.load() is False
