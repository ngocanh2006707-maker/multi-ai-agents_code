"""Validation + cleaning + chunking cho Knowledge Base baseline."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from knowledge_base.chunking import chunk_document, clean_text

_REQUIRED_FIELDS = {
    "document_id",
    "title",
    "source",
    "timestamp",
    "trust_level",
    "document_type",
    "topic",
    "content",
}


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def validate_document(raw_doc: dict) -> dict:
    """Validate schema tối thiểu và trả document đã chuẩn hóa."""
    missing = sorted(field for field in _REQUIRED_FIELDS if field not in raw_doc)
    if missing:
        raise ValueError(f"Document thiếu field bắt buộc: {missing}")

    content = clean_text(str(raw_doc.get("content", "")))
    if not content:
        raise ValueError("Document content không được rỗng")

    trust_level = float(raw_doc["trust_level"])
    if not 0.0 <= trust_level <= 1.0:
        raise ValueError("trust_level phải nằm trong [0, 1]")

    topic = raw_doc["topic"]
    if isinstance(topic, str):
        topic = [topic]
    if not isinstance(topic, list) or not all(isinstance(x, str) for x in topic):
        raise ValueError("topic phải là list[str] hoặc str")

    normalized = {
        **raw_doc,
        "document_id": str(raw_doc["document_id"]).strip(),
        "title": str(raw_doc["title"]).strip(),
        "source": str(raw_doc["source"]).strip(),
        "timestamp": str(raw_doc["timestamp"]).strip(),
        "trust_level": trust_level,
        "document_type": str(raw_doc["document_type"]).strip(),
        "topic": [x.strip() for x in topic if x.strip()],
        "content": content,
        "is_poisoned": bool(raw_doc.get("is_poisoned", False)),
        "attack_type": raw_doc.get("attack_type"),
        "experiment_id": raw_doc.get("experiment_id"),
    }
    normalized["content_hash"] = raw_doc.get("content_hash") or _sha256(content)
    return normalized


def ingest_document(
    raw_doc: dict,
    chunk_size: int = 900,
    overlap: int = 120,
) -> list[dict]:
    """Document -> Validation -> Cleaning -> Chunking."""
    document = validate_document(raw_doc)
    return chunk_document(document, chunk_size=chunk_size, overlap=overlap)


def load_jsonl(path: str | Path) -> list[dict]:
    """Đọc file JSONL, bỏ dòng trống và báo rõ dòng lỗi."""
    path = Path(path)
    documents: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                documents.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"JSONL lỗi tại dòng {line_no}: {exc}") from exc
    return documents


def ingest_jsonl(
    path: str | Path,
    chunk_size: int = 900,
    overlap: int = 120,
) -> list[dict]:
    """Đọc toàn bộ JSONL và trả danh sách chunk đã validate."""
    chunks: list[dict] = []
    seen_document_ids: set[str] = set()
    for raw_doc in load_jsonl(path):
        document_id = str(raw_doc.get("document_id", "")).strip()
        if document_id in seen_document_ids:
            raise ValueError(f"document_id bị trùng trong JSONL: {document_id!r}")
        seen_document_ids.add(document_id)
        chunks.extend(ingest_document(raw_doc, chunk_size, overlap))
    return chunks
