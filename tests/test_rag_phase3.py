from stage2_sdk_ai.api import health, query
from stage2_sdk_ai.rag_chain import query_rag
from stage2_sdk_ai.vector_store import RealVectorStore


def test_rag_chain_mock():
    store = RealVectorStore(persist_path=".test_rag_phase3")
    store.add_documents([{"text": "Termux is Android terminal", "metadata": [{"id": 1}]}])
    result = query_rag("What is Termux?", store, top_k=1)
    assert "query" in result
    assert "answer" in result
    assert "sources" in result
    assert len(result["sources"]) >= 1
    assert result["top_k"] == 1

def test_api_health():
    data = health()
    assert data["status"] == "ok"

def test_api_query():
    data = query(q="test query", top_k=1)
    assert "answer" in data
    assert "sources" in data
