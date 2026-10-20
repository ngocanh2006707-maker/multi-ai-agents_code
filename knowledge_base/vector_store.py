"""Vector store Chroma bền vững cho Knowledge Base baseline."""

from __future__ import annotations

import os
from functools import lru_cache

import chromadb
from chromadb.errors import NotFoundError


def _expected_embedding_metadata() -> dict[str, str]:
    return {
        "embedding_provider": os.environ.get(
            "EMBEDDING_PROVIDER", "google"
        ).strip().lower(),
        "embedding_model": os.environ.get(
            "EMBEDDING_MODEL", "gemini-embedding-2"
        ).strip(),
    }


def _new_collection_metadata() -> dict[str, str]:
    return {"hnsw:space": "cosine", **_expected_embedding_metadata()}


@lru_cache(maxsize=1)
def get_client():
    path = os.environ.get("VECTOR_DB_PATH", "./data/vector_db")
    return chromadb.PersistentClient(path=path)


@lru_cache(maxsize=1)
def get_vector_store():
    collection_name = os.environ.get(
        "VECTOR_DB_COLLECTION", "ai_agent_security_kb"
    )
    return get_client().get_or_create_collection(
        name=collection_name,
        metadata=_new_collection_metadata(),
    )


def _validate_embedding_fingerprint(
    collection,
    dimension: int,
    *,
    allow_legacy: bool,
) -> None:
    """Không cho trộn vector từ model hoặc dimension khác nhau."""
    metadata = dict(collection.metadata or {})
    expected = _expected_embedding_metadata()
    missing_fingerprint = any(key not in metadata for key in expected)

    if collection.count() and missing_fingerprint:
        if allow_legacy:
            return
        raise ValueError(
            "Collection cũ chưa có embedding fingerprint. "
            "Hãy rebuild Knowledge Base bằng --reset trước khi upsert."
        )

    for key, expected_value in expected.items():
        stored_value = metadata.get(key)
        if stored_value is not None and stored_value != expected_value:
            raise ValueError(
                f"Collection dùng {key}={stored_value!r}, nhưng cấu hình hiện tại "
                f"là {expected_value!r}. Hãy dùng collection khác hoặc rebuild --reset."
            )

    stored_dimension = metadata.get("embedding_dimension")
    if stored_dimension is not None and int(stored_dimension) != dimension:
        raise ValueError(
            f"Embedding dimension không khớp: collection={stored_dimension}, "
            f"input={dimension}. Hãy rebuild Knowledge Base bằng --reset."
        )

    if not collection.count() and (
        missing_fingerprint or stored_dimension is None
    ):
        # Chroma xem các khóa cấu hình HNSW là bất biến. Truyền ``hnsw:space``
        # hiện có lại cho ``modify`` sẽ bị hiểu là cố thay đổi hàm khoảng cách
        # và thất bại ngay cả khi giá trị không đổi. Ở đây chỉ cập nhật
        # metadata thông thường của collection; cấu hình cosine lúc tạo
        # collection vẫn được giữ nguyên.
        mutable_metadata = {
            key: value
            for key, value in metadata.items()
            if not key.startswith("hnsw:")
        }
        collection.modify(
            metadata={
                **mutable_metadata,
                **expected,
                "embedding_dimension": dimension,
            }
        )


def reset_vector_store():
    """Xóa collection hiện tại và tạo lại. Chỉ dùng khi chủ động xây KB."""
    client = get_client()
    name = os.environ.get("VECTOR_DB_COLLECTION", "ai_agent_security_kb")
    try:
        client.delete_collection(name)
    except NotFoundError:
        # Collection chưa tồn tại là trạng thái hợp lệ khi reset lần đầu.
        pass
    get_vector_store.cache_clear()
    return get_vector_store()


def upsert_chunks(chunks: list[dict], embeddings: list[list[float]]) -> int:
    """Upsert chunk + embedding vào Chroma và trả số chunk đã ghi."""
    if len(chunks) != len(embeddings):
        raise ValueError("Số chunks và embeddings phải bằng nhau")
    if not chunks:
        return 0

    dimensions = {len(vector) for vector in embeddings}
    if len(dimensions) != 1 or 0 in dimensions:
        raise ValueError("Mọi embedding phải có cùng dimension và không được rỗng")

    collection = get_vector_store()
    ids = [chunk["chunk_id"] for chunk in chunks]
    if len(ids) != len(set(ids)):
        raise ValueError("Phát hiện chunk_id trùng trong batch upsert")

    _validate_embedding_fingerprint(
        collection,
        dimensions.pop(),
        allow_legacy=False,
    )

    incoming_ids_by_document: dict[str, set[str]] = {}
    for chunk in chunks:
        document_id = str(chunk.get("document_id", "")).strip()
        if not document_id:
            raise ValueError("Mọi chunk phải có document_id không rỗng")
        incoming_ids_by_document.setdefault(document_id, set()).add(
            chunk["chunk_id"]
        )

    stale_ids: list[str] = []
    for document_id, incoming_ids in incoming_ids_by_document.items():
        existing = collection.get(
            where={"document_id": document_id},
            include=[],
        )
        existing_ids = set(existing.get("ids") or [])
        stale_ids.extend(sorted(existing_ids - incoming_ids))

    documents = [chunk["content"] for chunk in chunks]
    metadatas = [
        {k: v for k, v in chunk.items() if k != "content" and v is not None}
        for chunk in chunks
    ]
    collection.upsert(
        ids=ids,
        documents=documents,
        metadatas=metadatas,
        embeddings=embeddings,
    )
    if stale_ids:
        collection.delete(ids=stale_ids)
    return len(chunks)


def query_by_embedding(query_embedding: list[float], n_results: int = 5) -> dict:
    collection = get_vector_store()
    if collection.count() == 0:
        return {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}

    _validate_embedding_fingerprint(
        collection,
        len(query_embedding),
        allow_legacy=True,
    )

    n_results = max(1, min(n_results, collection.count()))
    return collection.query(
        query_embeddings=[query_embedding],
        n_results=n_results,
        include=["documents", "metadatas", "distances"],
    )


def collection_count() -> int:
    return get_vector_store().count()
