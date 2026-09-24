"""Validation + cleaning + chunking cho Knowledge Base baseline."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from knowledge_base.chunking import chunk_document, clean_text
from security.source_trust import assign_system_trust

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


@dataclass
class IngestionBatch:
    chunks: list[dict]
    quarantined: list[dict]


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def validate_document(raw_doc: dict, *, use_managed_trust: bool = True) -> dict:
    """Validate schema tối thiểu và trả document đã chuẩn hóa."""
    missing = sorted(field for field in _REQUIRED_FIELDS if field not in raw_doc)
    if missing:
        raise ValueError(f"Document thiếu field bắt buộc: {missing}")

    content = clean_text(str(raw_doc.get("content", "")))
    if not content:
        raise ValueError("Document content không được rỗng")

    claimed_trust_level = float(raw_doc["trust_level"])
    if not 0.0 <= claimed_trust_level <= 1.0:
        raise ValueError("trust_level phải nằm trong [0, 1]")

    topic = raw_doc["topic"]
    if isinstance(topic, str):
        topic = [topic]
    if not isinstance(topic, list) or not all(isinstance(x, str) for x in topic):
        raise ValueError("topic phải là list[str] hoặc str")

    source = str(raw_doc["source"]).strip()
    trust_assignment = assign_system_trust(source)
    normalized = {
        **raw_doc,
        "document_id": str(raw_doc["document_id"]).strip(),
        "title": str(raw_doc["title"]).strip(),
        "source": source,
        "timestamp": str(raw_doc["timestamp"]).strip(),
        # Defense Off giữ nguyên claim của tài liệu để tạo baseline ít phòng thủ.
        # Defense On mới dùng trust do registry của hệ thống quản lý.
        "trust_level": (
            trust_assignment.trust_level
            if use_managed_trust
            else claimed_trust_level
        ),
        # Chỉ giữ claim của tài liệu để audit; không dùng cho rerank/guard.
        "claimed_trust_level": claimed_trust_level,
        "trust_managed": use_managed_trust,
        "trust_policy_id": trust_assignment.policy_id,
        "source_allowlisted": trust_assignment.allowed,
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
    *,
    use_managed_trust: bool = True,
) -> list[dict]:
    """Đọc toàn bộ JSONL và trả danh sách chunk đã validate."""
    return ingest_jsonl_partitioned(
        path,
        chunk_size=chunk_size,
        overlap=overlap,
        enforce_source_allowlist=False,
        use_managed_trust=use_managed_trust,
    ).chunks


def ingest_jsonl_partitioned(
    path: str | Path,
    chunk_size: int = 900,
    overlap: int = 120,
    *,
    enforce_source_allowlist: bool,
    use_managed_trust: bool = True,
) -> IngestionBatch:
    """Validate tài liệu và tách nguồn chưa duyệt khi policy được enforce."""
    chunks: list[dict] = []
    quarantined: list[dict] = []
    seen_document_ids: set[str] = set()
    for raw_doc in load_jsonl(path):
        document_id = str(raw_doc.get("document_id", "")).strip()
        if document_id in seen_document_ids:
            raise ValueError(f"document_id bị trùng trong JSONL: {document_id!r}")
        seen_document_ids.add(document_id)
        document = validate_document(
            raw_doc,
            use_managed_trust=use_managed_trust,
        )
        if enforce_source_allowlist and not document["source_allowlisted"]:
            quarantined.append({
                "quarantine_reason": "source_not_allowlisted",
                "document": document,
            })
            continue
        chunks.extend(
            chunk_document(document, chunk_size=chunk_size, overlap=overlap)
        )
    return IngestionBatch(chunks=chunks, quarantined=quarantined)
