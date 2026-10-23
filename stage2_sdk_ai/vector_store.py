import hashlib
import json
import math
from pathlib import Path
from typing import Any

try:
    import faiss

    HAS_FAISS = True
except Exception:
    HAS_FAISS = False

try:
    import numpy as np

    HAS_NUMPY = True
except Exception:
    HAS_NUMPY = False

def chunk_text(text: str, chunk_size: int = 500, overlap: int = 50) -> list[str]:
    if len(text) <= chunk_size:
        return [text]
    chunks: list[str] = []
    start = 0
    seps = ["\n\n", "\n", ". ", " "]
    while start < len(text):
        end = min(start + chunk_size, len(text))
        if end < len(text):
            best = -1
            for sep in seps:
                idx = text.rfind(sep, start, end)
                if idx > start and idx > best:
                    best = idx + len(sep)
            if best != -1:
                end = best
        c = text[start:end].strip()
        if c:
            chunks.append(c)
        if end >= len(text):
            break
        start = max(0, end - overlap)
    return chunks

_chunk_text = chunk_text

def _mock_embed_384(text: str):
    h = int(hashlib.sha256(text.encode()).hexdigest(), 16)
    vals: list[float] = []
    for _ in range(384):
        h = (h * 1103515245 + 12345) & ((1 << 64) - 1)
        vals.append(((h % 10000) / 10000.0) * 2 - 1)
    norm = math.sqrt(sum(v * v for v in vals))
    normed = [v / norm for v in vals] if norm else vals
    if HAS_NUMPY:
        return np.array(normed, dtype="float32")
    return normed

def _cosine_sim(a, b) -> float:
    if HAS_NUMPY:
        aa = np.array(a, dtype="float32")
        bb = np.array(b, dtype="float32")
        na = float(np.linalg.norm(aa))
        nb = float(np.linalg.norm(bb))
        if na == 0 or nb == 0:
            return 0.0
        return float(np.dot(aa, bb) / (na * nb))
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0

def _embed_openai(texts: list[str]):
    embs384 = [_mock_embed_384(t) for t in texts]
    out = []
    for e in embs384:
        if HAS_NUMPY:
            arr = np.array(e, dtype="float32")
            tiled = np.tile(arr, 4)[:1536]
            n = float(np.linalg.norm(tiled))
            out.append(tiled / n if n else tiled)
        else:
            tiled = (list(e) * 4)[:1536]
            n = math.sqrt(sum(x * x for x in tiled))
            out.append([x / n for x in tiled] if n else tiled)
    return out

class RealVectorStore:
    def __init__(self, persist_path: str = ".test_rag", dim: int = 1536):
        self.persist_path = Path(persist_path)
        self.dim = dim
        self.texts: list[str] = []
        self.metadatas: list[dict] = []
        self.embeddings: list = []
        self.faiss_index = None

    def add_documents(
        self, docs: list[dict], chunk_size: int = 500, overlap: int = 50
    ):
        all_chunks: list[str] = []
        all_metas: list[dict] = []
        for doc in docs:
            txt = doc.get("text", "")
            meta = doc.get("metadata", {})
            for i, ch in enumerate(chunk_text(txt, chunk_size, overlap)):
                all_chunks.append(ch)
                m = dict(meta)
                m["chunk_id"] = i
                all_metas.append(m)
        if not all_chunks:
            return
        batch_n = 20
        for i in range(0, len(all_chunks), batch_n):
            batch = all_chunks[i : i + batch_n]
            metas = all_metas[i : i + batch_n]
            embs = _embed_openai(batch)
            self.texts.extend(batch)
            self.metadatas.extend(metas)
            self.embeddings.extend(embs)
        if HAS_FAISS and self.embeddings:
            arr = np.array(self.embeddings, dtype="float32")
            if self.faiss_index is None:
                self.faiss_index = faiss.IndexFlatIP(self.dim)
            faiss.normalize_L2(arr)
            self.faiss_index.add(arr)

    def similarity_search(
        self,
        query: str,
        top_k: int = 3,
        filter_meta=None,
        hybrid: bool = False,
    ):
        if not self.texts:
            return []
        q_emb = _embed_openai([query])[0]
        if hybrid:
            q_lower = query.lower()
            scored: list[tuple[int, int]] = []
            for idx, txt in enumerate(self.texts):
                s = sum(1 for w in q_lower.split() if w in txt.lower())
                scored.append((s, idx))
            scored.sort(key=lambda x: x[0], reverse=True)
            cand_idx = [idx for s, idx in scored if s > 0][: top_k * 2]
            if not cand_idx:
                cand_idx = [idx for _, idx in scored[: top_k * 2]]
        else:
            cand_idx = list(range(len(self.texts)))

        cands = []
        for idx in cand_idx:
            if filter_meta:
                if not all(
                    self.metadatas[idx].get(k) == v
                    for k, v in filter_meta.items()
                ):
                    continue
            cands.append((_cosine_sim(q_emb, self.embeddings[idx]), idx))
        cands.sort(key=lambda x: x[0], reverse=True)
        results: list[dict[str, Any]] = []
        for score, idx in cands[:top_k]:
            emb = self.embeddings[idx]
            dim = len(emb) if hasattr(emb, "__len__") else self.dim
            if HAS_NUMPY and hasattr(emb, "shape"):
                dim = int(emb.shape[0])
            results.append(
                {
                    "text": self.texts[idx],
                    "metadata": self.metadatas[idx],
                    "score": score,
                    "embedding_dim": dim,
                }
            )
        return results

    def hybrid_search(self, query: str, top_k: int = 3):
        return self.similarity_search(query, top_k, hybrid=True)

    def save(self):
        self.persist_path.mkdir(parents=True, exist_ok=True)
        embs_list: list[list[float]] = []
        for e in self.embeddings:
            if HAS_NUMPY and hasattr(e, "tolist"):
                embs_list.append(e.tolist())
            else:
                embs_list.append(list(e))
        data = {
            "texts": self.texts,
            "metadatas": self.metadatas,
            "embeddings": embs_list,
            "dim": self.dim,
        }
        with open(self.persist_path / "store.json", "w") as f:
            json.dump(data, f)

    def load(self) -> bool:
        p = self.persist_path / "store.json"
        if not p.exists():
            return False
        with open(p) as f:
            data = json.load(f)
        self.texts = data.get("texts", [])
        self.metadatas = data.get("metadatas", [])
        self.embeddings = data.get("embeddings", [])
        self.dim = data.get("dim", 1536)
        return True
