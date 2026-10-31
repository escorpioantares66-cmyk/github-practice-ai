from __future__ import annotations

import hashlib
import json
import math
import os
import pathlib
import stat
from typing import Any

from .secure_storage import open_private_file, write_text_atomically

try:
    import faiss  # type: ignore

    FAISS_AVAILABLE = True
except Exception:
    FAISS_AVAILABLE = False
    faiss = None  # type: ignore

try:
    import numpy as np

    NUMPY_AVAILABLE = True
except Exception:
    NUMPY_AVAILABLE = False
    np = None  # type: ignore

MAX_CHUNK_SIZE = 10_000
MAX_DOCUMENT_CHARS = 100_000
MAX_DOCUMENTS = 1_000
MAX_CHUNKS = 10_000
MAX_QUERY_CHARS = 10_000
MAX_TOP_K = 100
MAX_STORE_BYTES = 64 * 1024 * 1024
EMBEDDING_DIM = 1536


def _chunk_text(text: str, chunk_size: int = 500, overlap: int = 50) -> list[str]:
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int):
        raise ValueError("chunk_size must be an integer")
    if isinstance(overlap, bool) or not isinstance(overlap, int):
        raise ValueError("overlap must be an integer")
    if not 1 <= chunk_size <= MAX_CHUNK_SIZE:
        raise ValueError(f"chunk_size must be between 1 and {MAX_CHUNK_SIZE}")
    if not 0 <= overlap < chunk_size:
        raise ValueError("overlap must be non-negative and smaller than chunk_size")
    if not text:
        return []

    chunks: list[str] = []
    start = 0
    n = len(text)
    while start < n:
        end = min(start + chunk_size, n)
        chunks.append(text[start:end])
        if end >= n:
            break
        next_start = end - overlap
        if next_start <= start:
            raise ValueError("chunk parameters do not advance the input position")
        start = next_start
    return chunks


def _mock_embed_384d(text: str) -> Any:
    h = hashlib.sha256(text.encode("utf-8")).digest()
    vec: list[float] = []
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
    if NUMPY_AVAILABLE and np is not None:
        return np.array(vec, dtype=np.float32)
    return vec


def _mock_embed_384(text: str) -> Any:
    return _mock_embed_384d(text)


def _tile_384_to_1536(vec_384: Any) -> Any:
    values = list(vec_384.tolist() if hasattr(vec_384, "tolist") else vec_384)
    tiled = (values * 4)[:EMBEDDING_DIM]
    norm = math.sqrt(sum(float(x) * float(x) for x in tiled))
    if norm > 0:
        tiled = [float(x) / norm for x in tiled]
    if NUMPY_AVAILABLE and np is not None:
        return np.array(tiled, dtype=np.float32)
    return tiled


def _mock_mode_enabled() -> bool:
    flag = os.getenv("STAGE2_SDK_AI_MOCK_MODE", "").strip().lower()
    key = os.getenv("OPENAI_API_KEY", "")
    return flag in {"1", "true", "yes"} or key.startswith("sk-test-mocked")


def _validated_embedding(values: Any) -> Any:
    raw = values.tolist() if hasattr(values, "tolist") else list(values)
    if len(raw) != EMBEDDING_DIM:
        raise ValueError("Embedding has an unexpected dimension")
    vector = [float(value) for value in raw]
    if not all(math.isfinite(value) for value in vector):
        raise ValueError("Embedding contains a non-finite value")
    if NUMPY_AVAILABLE and np is not None:
        return np.array(vector, dtype=np.float32)
    return vector


def _get_query_embedding(text: str) -> tuple[Any, int, bool]:
    if not isinstance(text, str) or not text or len(text) > MAX_QUERY_CHARS:
        raise ValueError("Embedding input must be non-empty text within the size limit")

    key = os.getenv("OPENAI_API_KEY", "")
    if _mock_mode_enabled():
        vector = _tile_384_to_1536(_mock_embed_384d(text))
        return _validated_embedding(vector), EMBEDDING_DIM, True
    if not key:
        raise RuntimeError(
            "OPENAI_API_KEY is required; set STAGE2_SDK_AI_MOCK_MODE=1 only for tests"
        )

    try:
        from openai import OpenAI  # type: ignore

        client = OpenAI(api_key=key)
        response = client.embeddings.create(
            model="text-embedding-3-small", input=text
        )
        embedding = _validated_embedding(response.data[0].embedding)
        return embedding, EMBEDDING_DIM, False
    except Exception as exc:
        raise RuntimeError("OpenAI embedding request failed") from exc


def _cosine_sim(a: Any, b: Any) -> float:
    la = list(a.tolist() if hasattr(a, "tolist") else a)
    lb = list(b.tolist() if hasattr(b, "tolist") else b)
    if len(la) != len(lb) or not la:
        raise ValueError("Embedding dimensions do not match")
    if not all(math.isfinite(float(value)) for value in la + lb):
        raise ValueError("Embedding contains a non-finite value")
    return sum(float(x) * float(y) for x, y in zip(la, lb, strict=True))


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


class RealVectorStore:
    def __init__(self, persist_path: str = ".test_rag") -> None:
        self.persist_path = os.fspath(persist_path)
        self.texts: list[str] = []
        self.metadatas: list[dict[str, Any]] = []
        self.embeddings: list[Any] = []
        self.embedding_dim = EMBEDDING_DIM
        self._faiss_index: Any = None
        self._reset_faiss_index()

    def _reset_faiss_index(self) -> None:
        self._faiss_index = None
        if FAISS_AVAILABLE and faiss is not None:
            try:
                self._faiss_index = faiss.IndexFlatIP(self.embedding_dim)
            except Exception:
                self._faiss_index = None

    def add_documents(
        self, docs: list[dict[str, Any]], chunk_size: int = 500, overlap: int = 50
    ) -> None:
        if not isinstance(docs, list) or len(docs) > MAX_DOCUMENTS:
            raise ValueError(f"docs must be a list of at most {MAX_DOCUMENTS} items")
        pending = []
        total_chunks = len(self.texts)
        for doc in docs:
            if not isinstance(doc, dict):
                raise ValueError("each document must be an object")
            raw_text = doc.get("text", "")
            if not isinstance(raw_text, str):
                raise ValueError("document text must be a string")
            if len(raw_text) > MAX_DOCUMENT_CHARS:
                raise ValueError("document text exceeds the size limit")
            raw_meta = doc.get("metadata", {})
            if isinstance(raw_meta, list):
                meta = raw_meta[0] if raw_meta and isinstance(raw_meta[0], dict) else {}
            elif isinstance(raw_meta, dict):
                meta = raw_meta
            else:
                raise ValueError("document metadata must be an object or list of objects")
            chunks = _chunk_text(raw_text, chunk_size, overlap)
            if not chunks:
                chunks = [raw_text]
            total_chunks += len(chunks)
            if total_chunks > MAX_CHUNKS:
                raise ValueError(f"vector store cannot exceed {MAX_CHUNKS} chunks")
            pending.extend((chunk, meta) for chunk in chunks)

        staged_embeddings = []
        for chunk, metadata in pending:
            embedding, dimension, _ = _get_query_embedding(chunk or " ")
            if dimension != EMBEDDING_DIM:
                raise ValueError("Unexpected embedding dimension")
            staged_embeddings.append((chunk, metadata, embedding))

        # Commit the in-memory mutation only after every embedding succeeds.
        self.texts.extend(chunk for chunk, _, _ in staged_embeddings)
        self.metadatas.extend(metadata for _, metadata, _ in staged_embeddings)
        self.embeddings.extend(embedding for _, _, embedding in staged_embeddings)
        if (
            self._faiss_index is not None
            and staged_embeddings
            and NUMPY_AVAILABLE
            and np is not None
        ):
            try:
                matrix = np.vstack(
                    [np.asarray(item[2], dtype=np.float32) for item in staged_embeddings]
                )
                self._faiss_index.add(matrix)
            except Exception:
                # Similarity search uses the validated vectors directly; discard
                # the optional acceleration index rather than corrupting state.
                self._faiss_index = None

    def similarity_search(
        self,
        query: str,
        top_k: int = 5,
        filter_meta: dict[str, Any] | None = None,
        hybrid: bool = False,
    ) -> list[dict[str, Any]]:
        if not isinstance(query, str) or not query.strip() or len(query) > MAX_QUERY_CHARS:
            raise ValueError("query must be non-empty text within the size limit")
        if isinstance(top_k, bool) or not isinstance(top_k, int) or not 0 <= top_k <= MAX_TOP_K:
            raise ValueError(f"top_k must be between 0 and {MAX_TOP_K}")
        if filter_meta is not None and not isinstance(filter_meta, dict):
            raise ValueError("filter_meta must be an object")
        if not isinstance(hybrid, bool):
            raise ValueError("hybrid must be a boolean")
        if not self.texts or top_k == 0:
            return []

        query_embedding, _, _ = _get_query_embedding(query)
        scored: list[tuple[float, int]] = []
        query_lower = query.lower()
        for index, (text, embedding, metadata) in enumerate(
            zip(self.texts, self.embeddings, self.metadatas, strict=True)
        ):
            if filter_meta and not all(
                metadata.get(key) == value for key, value in filter_meta.items()
            ):
                continue
            score = _cosine_sim(query_embedding, embedding)
            if hybrid and query_lower in text.lower():
                score += 0.1
            scored.append((score, index))

        scored.sort(key=lambda item: item[0], reverse=True)
        return [
            {
                "text": self.texts[index],
                "metadata": self.metadatas[index],
                "score": float(score),
                "embedding_dim": self.embedding_dim,
            }
            for score, index in scored[:top_k]
        ]

    def save(self) -> None:
        if not (
            len(self.texts) == len(self.metadatas) == len(self.embeddings)
            and len(self.texts) <= MAX_CHUNKS
            and self.embedding_dim == EMBEDDING_DIM
        ):
            raise ValueError("Vector store state is inconsistent")
        values = []
        for embedding in self.embeddings:
            vector = _validated_embedding(embedding)
            values.append(
                vector.tolist() if hasattr(vector, "tolist") else list(vector)
            )
        data = {
            "texts": self.texts,
            "metadatas": self.metadatas,
            "embeddings": values,
            "embedding_dim": self.embedding_dim,
        }
        serialized = json.dumps(data, ensure_ascii=False, allow_nan=False)
        if len(serialized.encode("utf-8")) > MAX_STORE_BYTES:
            raise ValueError("Vector store exceeds the persistence size limit")
        destination = pathlib.Path(self.persist_path) / "store.json"
        write_text_atomically(destination, serialized, pathlib.Path(self.persist_path))

    def load(self) -> bool:
        path = pathlib.Path(self.persist_path) / "store.json"
        fd = -1
        try:
            fd = open_private_file(path, os.O_RDONLY)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_STORE_BYTES:
                return False
            with os.fdopen(fd, "r", encoding="utf-8") as handle:
                fd = -1
                serialized = handle.read(MAX_STORE_BYTES + 1)
            if len(serialized.encode("utf-8")) > MAX_STORE_BYTES:
                return False
            data = json.loads(serialized, object_pairs_hook=_reject_duplicate_keys)
            if not isinstance(data, dict):
                return False

            texts = data.get("texts")
            metadatas = data.get("metadatas")
            raw_embeddings = data.get("embeddings")
            dimension = data.get("embedding_dim")
            if (
                not isinstance(texts, list)
                or not isinstance(metadatas, list)
                or not isinstance(raw_embeddings, list)
                or len(texts) != len(metadatas)
                or len(texts) != len(raw_embeddings)
                or len(texts) > MAX_CHUNKS
                or dimension != EMBEDDING_DIM
            ):
                return False

            validated_texts = []
            validated_metadata = []
            validated_embeddings = []
            for text, metadata, embedding in zip(
                texts, metadatas, raw_embeddings, strict=True
            ):
                if (
                    not isinstance(text, str)
                    or len(text) > MAX_DOCUMENT_CHARS
                    or not isinstance(metadata, dict)
                    or not isinstance(embedding, list)
                ):
                    return False
                validated_texts.append(text)
                validated_metadata.append(metadata)
                validated_embeddings.append(_validated_embedding(embedding))

            self.texts = validated_texts
            self.metadatas = validated_metadata
            self.embeddings = validated_embeddings
            self.embedding_dim = EMBEDDING_DIM
            self._reset_faiss_index()
            if (
                self._faiss_index is not None
                and self.embeddings
                and NUMPY_AVAILABLE
                and np is not None
            ):
                matrix = np.vstack(self.embeddings).astype(np.float32, copy=False)
                self._faiss_index.add(matrix)
            return True
        except (OSError, UnicodeError, ValueError, TypeError, KeyError):
            self.texts = []
            self.metadatas = []
            self.embeddings = []
            self.embedding_dim = EMBEDDING_DIM
            self._reset_faiss_index()
            return False
        finally:
            if fd >= 0:
                os.close(fd)
