"""Chunking đơn giản cho Knowledge Base baseline (Phase 4)."""

from __future__ import annotations

import hashlib
import re


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def clean_text(text: str) -> str:
    """Chuẩn hóa khoảng trắng nhưng giữ nội dung nguyên nghĩa."""
    return re.sub(r"\s+", " ", text or "").strip()


def chunk_document(
    document: dict,
    chunk_size: int = 900,
    overlap: int = 120,
) -> list[dict]:
    """Chia document theo số ký tự, ưu tiên cắt ở ranh giới từ.

    Baseline cố ý đơn giản để dễ debug. Metadata document được sao chép
    xuống từng chunk; `topic` được giữ ở dạng chuỗi phân cách bằng dấu phẩy
    để tương thích metadata scalar của Chroma.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size phải > 0")
    if overlap < 0 or overlap >= chunk_size:
        raise ValueError("overlap phải >= 0 và nhỏ hơn chunk_size")

    text = clean_text(document.get("content", ""))
    if not text:
        return []

    chunks: list[dict] = []
    start = 0
    index = 0

    while start < len(text):
        end = min(start + chunk_size, len(text))
        if end < len(text):
            # Tránh cắt giữa từ: tìm khoảng trắng gần cuối chunk.
            boundary = text.rfind(" ", start, end)
            if boundary > start + chunk_size // 2:
                end = boundary

        content = text[start:end].strip()
        if content:
            document_id = document["document_id"]
            chunks.append(
                {
                    "chunk_id": f"{document_id}_chunk_{index:02d}",
                    "document_id": document_id,
                    "content": content,
                    "title": document.get("title", ""),
                    "source": document.get("source", ""),
                    "timestamp": document.get("timestamp", ""),
                    "trust_level": float(document.get("trust_level", 0.5)),
                    "claimed_trust_level": float(
                        document.get("claimed_trust_level", 0.0)
                    ),
                    "trust_managed": document.get("trust_managed") is True,
                    "trust_policy_id": document.get("trust_policy_id", ""),
                    "source_allowlisted": (
                        document.get("source_allowlisted") is True
                    ),
                    "content_hash": _sha256(content),
                    "document_hash": document.get("content_hash", ""),
                    "document_type": document.get("document_type", "unknown"),
                    "topic": ",".join(document.get("topic", [])),
                    "chunk_index": index,
                    # Trường thí nghiệm: giữ trong DB để đo lường nhưng
                    # retrieval.py sẽ không trả cho Agent ở baseline.
                    "is_poisoned": bool(document.get("is_poisoned", False)),
                    "attack_type": document.get("attack_type") or "",
                    "experiment_id": document.get("experiment_id") or "",
                }
            )
            index += 1

        if end >= len(text):
            break
        start = max(end - overlap, start + 1)

    return chunks
