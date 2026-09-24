"""Semantic retrieval; trust-aware reranking chỉ bật ở Defense On."""

from __future__ import annotations

import os

from security.config import load_security_settings


def _minimum_similarity() -> float:
    """Đọc ngưỡng relevance và fail rõ ràng nếu cấu hình không hợp lệ."""
    value = float(os.environ.get("RETRIEVAL_MIN_SIMILARITY", "0.20"))
    if not 0.0 <= value <= 1.0:
        raise ValueError("RETRIEVAL_MIN_SIMILARITY phải nằm trong [0, 1]")
    return value

def _cosine_distance_to_similarity(distance: float) -> float:
    # Chroma cosine distance = 1 - cosine_similarity. Cosine similarity
    # về lý thuyết có thể âm, nhưng score hiển thị cho Agent được chặn [0,1].
    return max(0.0, min(1.0, 1.0 - float(distance)))


def rerank_results(
    results: list[dict],
    *,
    trust_aware: bool | None = None,
) -> list[dict]:
    """Xếp hạng semantic-only ở Defense Off, có xét trust ở Defense On.

    adjusted_score = similarity * (0.70 + 0.30 * trust_level)
    => nguồn trust thấp bị giảm hạng nhưng không bị loại hoàn toàn khi bật defense.
    """
    if trust_aware is None:
        trust_aware = load_security_settings().trust_aware_ranking

    for item in results:
        similarity = float(item["similarity_score"])
        if trust_aware:
            trust = max(0.0, min(1.0, float(item.get("trust_level", 0.5))))
            item["_ranking_score"] = similarity * (0.70 + 0.30 * trust)
        else:
            item["_ranking_score"] = similarity
    results.sort(key=lambda x: x["_ranking_score"], reverse=True)
    return results


def search(query: str, top_k: int = 5) -> list[dict]:
    """Tìm top-k chunk và trả schema an toàn cho Research Agent.

    Các nhãn thí nghiệm như `is_poisoned` KHÔNG được trả ra Agent để tránh
    làm lộ đáp án khi chạy data/knowledge poisoning sau này.
    """
    query = (query or "").strip()
    if not query:
        return []
    top_k = int(top_k)
    if top_k <= 0:
        return []

    from knowledge_base.embeddings import embed_query
    from knowledge_base.vector_store import query_by_embedding

    query_embedding = embed_query(query)
    # Lấy nhiều ứng viên hơn để trust-aware reranking có không gian sắp xếp.
    raw = query_by_embedding(query_embedding, n_results=top_k * 3)

    ids = (raw.get("ids") or [[]])[0]
    documents = (raw.get("documents") or [[]])[0]
    metadatas = (raw.get("metadatas") or [[]])[0]
    distances = (raw.get("distances") or [[]])[0]

    candidates: list[dict] = []
    for chunk_id, content, metadata, distance in zip(
        ids, documents, metadatas, distances
    ):
        metadata = metadata or {}
        candidates.append(
            {
                "document_id": metadata.get("document_id", ""),
                "chunk_id": chunk_id,
                "content": content or "",
                "title": metadata.get("title", ""),
                "source": metadata.get("source", ""),
                "timestamp": metadata.get("timestamp", ""),
                "trust_level": float(metadata.get("trust_level", 0.5)),
                "trust_managed": metadata.get("trust_managed") is True,
                "trust_policy_id": metadata.get("trust_policy_id", ""),
                "source_allowlisted": (
                    metadata.get("source_allowlisted") is True
                ),
                "content_hash": metadata.get("content_hash", ""),
                "similarity_score": _cosine_distance_to_similarity(distance),
            }
        )

    candidates = [
        item
        for item in candidates
        if item["similarity_score"] >= _minimum_similarity()
    ]
    ranked = rerank_results(candidates)[:top_k]
    for item in ranked:
        item.pop("_ranking_score", None)
    return ranked
