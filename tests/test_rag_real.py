import os

os.environ.setdefault("OPENAI_API_KEY", "sk-test-mocked")

import pathlib
import shutil

from stage2_sdk_ai.vector_store import RealVectorStore, _chunk_text, _mock_embed_384


def test_chunking():
    text = "hello world. This is a test. " * 100
    chunks = _chunk_text(text, chunk_size=100, overlap=10)
    assert len(chunks) > 1
    assert all(len(c) <= 120 for c in chunks)

def test_mock_embed_384_dim():
    emb = _mock_embed_384("test")
    assert len(emb) == 384
    s = sum(x * x for x in (emb.tolist() if hasattr(emb, "tolist") else emb))
    assert abs(s - 1.0) < 0.1

def test_real_vector_store_add_and_search():
    store = RealVectorStore(persist_path=".test_rag")
    docs = [
        {"text": "Python is a programming language", "metadata": [{"source": "doc1"}]},
        {
            "text": "Termux is an Android terminal emulator",
            "metadata": [{"source": "doc2", "author": "Lee"}],
        },
    ]
    store.add_documents(docs, chunk_size=200, overlap=20)
    assert len(store.texts) >= 2
    results = store.similarity_search("programming language", top_k=2)
    assert len(results) >= 1
    assert "score" in results[0]
    assert results[0]["embedding_dim"] in [384, 1536]

def test_metadata_filtering():
    store = RealVectorStore(persist_path=".test_rag2")
    docs = [
        {"text": " Apple fruit", "metadata": [{"type": "fruit"}]},
        {"text": " Apple company", "metadata": [{"type": "tech"}]},
    ]
    store.add_documents(docs)
    results = store.similarity_search(
        "Apple", top_k=5, filter_meta={"type": "fruit"}
    )
    assert len(results) >= 1
    assert all(r["metadata"]["type"] == "fruit" for r in results)

def test_hybrid_search():
    store = RealVectorStore(persist_path=".test_rag3")
    docs = [{"text": "The quick brown fox", "metadata": [{}]}]
    store.add_documents(docs)
    results = store.similarity_search("quick fox", top_k=1, hybrid=True)
    assert len(results) == 1

def test_persistence():
    path = ".test_rag_persist"
    store = RealVectorStore(persist_path=path)
    docs = [{"text": "Persist me", "metadata": [{"id": 1}]}]
    store.add_documents(docs)
    store.save()
    store2 = RealVectorStore(persist_path=path)
    assert store2.load() is True
    assert len(store2.texts) >= 1
    shutil.rmtree(path, ignore_errors=True)
    shutil.rmtree(".test_rag", ignore_errors=True)
    shutil.rmtree(".test_rag2", ignore_errors=True)
    shutil.rmtree(".test_rag3", ignore_errors=True)

_ = pathlib.Path(".")
