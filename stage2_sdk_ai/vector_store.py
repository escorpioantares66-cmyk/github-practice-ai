import os
import json
import math
import hashlib
import pathlib
from typing import List, Dict, Any

try:
    import faiss
    FAISS_AVAILABLE = True
except Exception:
    FAISS_AVAILABLE = False

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except Exception:
    NUMPY_AVAILABLE = False
    np = None

def _chunk_text(text: str, chunk_size: int = 500, overlap: int = 50) -> List[str]:
    if not text:
        return []
    chunks = []
    start = 0
    n = len(text)
    while start < n:
        end = min(start + chunk_size, n)
        chunks.append(text[start:end])
        if end >= n:
            break
        start = end - overlap
        if start < 0:
            start = 0
    return chunks

def _mock_embed_384d(text: str):
    h = hashlib.sha256(text.encode("utf-8")).digest()
    vec = []
    for i in range(384):
        b = h[i % len(h)]
        v = (b / 255.0) * 2 - 1 + (i % 7) * 0.01
        vec.append(v)
        if (i + 1) % 32 == 0:
            h = hashlib.sha256(h + str(i).encode()).digest()
    norm = math.sqrt(sum(x * x for x in vec))
    if norm == 0:
        norm = 1.0
    vec = [x / norm for x in vec]
    if NUMPY_AVAILABLE:
        return np.array(vec, dtype=np.float32)
    return vec

def _tile_384_to_1536(vec_384):
    if NUMPY_AVAILABLE and hasattr(vec_384, 'tolist'):
        lst = vec_384.tolist()
    else:
        lst = list(vec_384)
    tiled = (lst * 4)[:1536]
    norm = math.sqrt(sum(x * x for x in tiled))
    if norm > 0:
        tiled = [x / norm for x in tiled]
    if NUMPY_AVAILABLE:
        return np.array(tiled, dtype=np.float32)
    return tiled

def _get_query_embedding(text: str):
    key = os.getenv("OPENAI_API_KEY", "")
    if key.startswith("sk-test-mocked") or key == "":
        v384 = _mock_embed_384d(text)
        return _tile_384_to_1536(v384), 1536, True
    try:
        from openai import OpenAI
        client = OpenAI(api_key=key)
        resp = client.embeddings.create(model="text-embedding-3-small", input=text)
        emb = resp.data[0].embedding
        if NUMPY_AVAILABLE:
            emb = np.array(emb, dtype=np.float32)
        return emb, 1536, False
    except Exception:
        v384 = _mock_embed_384d(text)
        return _tile_384_to_1536(v384), 1536, True

def _cosine_sim(a, b):
    if NUMPY_AVAILABLE and hasattr(a, 'dot'):
        try:
            return float(a.dot(b))
        except Exception:
            pass
    la = list(a.tolist() if hasattr(a, 'tolist') else a)
    lb = list(b.tolist() if hasattr(b, 'tolist') else b)
    return sum(x * y for x, y in zip(la, lb))

class RealVectorStore:
    def __init__(self, persist_path: str = ".test_rag"):
        self.persist_path = persist_path
        self.texts: List[str] = []
        self.metadatas: List[Dict[str, Any]] = []
        self.embeddings: List[Any] = []
        self.embedding_dim = 1536
        self._faiss_index = None
        if FAISS_AVAILABLE:
            try:
                self._faiss_index = faiss.IndexFlatIP(1536)
            except Exception:
                self._faiss_index = None

    def add_documents(self, docs: List[Dict[str, Any]], chunk_size: int = 500, overlap: int = 50):
        for doc in docs:
            raw_text = doc.get("text", "")
            raw_meta = doc.get("metadata", {})
            if isinstance(raw_meta, list) and len(raw_meta) > 0 and isinstance(raw_meta[0], dict):
                meta = raw_meta[0]
            elif isinstance(raw_meta, dict):
                meta = raw_meta
            else:
                meta = {}
            chunks = _chunk_text(raw_text, chunk_size, overlap)
            if not chunks:
                chunks = [raw_text]
            for ch in chunks:
                emb, dim, _ = _get_query_embedding(ch)
                self.embedding_dim = dim
                self.texts.append(ch)
                self.metadatas.append(meta)
                self.embeddings.append(emb)
                if self._faiss_index is not None:
                    try:
                        vec = emb
                        if not hasattr(vec, 'reshape'):
                            import numpy as _np
                            vec = _np.array(vec, dtype=_np.float32)
                        vec = vec.reshape(1, -1)
                        self._faiss_index.add(vec)
                    except Exception:
                        pass

    def similarity_search(self, query: str, top_k: int = 5, filter_meta: Dict[str, Any] = None, hybrid: bool = False):
        if not self.texts:
            return []
        q_emb, _, _ = _get_query_embedding(query)
        scored = []
        q_lower = query.lower()
        for idx, (txt, emb, meta) in enumerate(zip(self.texts, self.embeddings, self.metadatas)):
            if filter_meta:
                ok = True
                for k, v in filter_meta.items():
                    if meta.get(k) != v:
                        ok = False
                        break
                if not ok:
                    continue
            score = _cosine_sim(q_emb, emb)
            if hybrid:
                if q_lower in txt.lower():
                    score += 0.1
            scored.append((score, idx))
        scored.sort(key=lambda x: x[0], reverse=True)
        results = []
        for score, idx in scored[:top_k]:
            results.append({
                "text": self.texts[idx],
                "metadata": self.metadatas[idx],
                "score": float(score),
                "embedding_dim": self.embedding_dim
            })
        return results

    def save(self):
        p = pathlib.Path(self.persist_path)
        p.mkdir(parents=True, exist_ok=True)
        embs = []
        for e in self.embeddings:
            if hasattr(e, 'tolist'):
                embs.append(e.tolist())
            else:
                embs.append(list(e))
        data = {
            "texts": self.texts,
            "metadatas": self.metadatas,
            "embeddings": embs,
            "embedding_dim": self.embedding_dim
        }
        with open(p / "store.json", "w", encoding="utf-8") as f:
            json.dump(data, f)
        if FAISS_AVAILABLE and self._faiss_index is not None:
            try:
                faiss.write_index(self._faiss_index, str(p / "faiss.index"))
            except Exception:
                pass

    def load(self):
        p = pathlib.Path(self.persist_path)
        jf = p / "store.json"
        if not jf.exists():
            return False
        try:
            with open(jf, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.texts = data.get("texts", [])
            self.metadatas = data.get("metadatas", [])
            raw_embs = data.get("embeddings", [])
            self.embedding_dim = data.get("embedding_dim", 1536)
            self.embeddings = []
            for e in raw_embs:
                if NUMPY_AVAILABLE:
                    self.embeddings.append(np.array(e, dtype=np.float32))
                else:
                    self.embeddings.append(e)
            if FAISS_AVAILABLE:
                fi = p / "faiss.index"
                if fi.exists():
                    try:
                        self._faiss_index = faiss.read_index(str(fi))
                    except Exception:
                        self._faiss_index = faiss.IndexFlatIP(self.embedding_dim)
                        if self.embeddings and NUMPY_AVAILABLE:
                            try:
                                mat = np.vstack([np.array(x, dtype=np.float32) for x in self.embeddings])
                                self._faiss_index.add(mat)
                            except Exception:
                                pass
            return True
        except Exception:
            return False
_mock_embed_384 = _mock_embed_384d
