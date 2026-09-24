"""
Vị trí phòng thủ: Research -> [Retrieval Defense] -> Planner (mục 13),
và Knowledge Base -> [Knowledge Validation].

Khi defense_off: phát hiện ở chế độ monitor-only nhưng không lọc.
Khi defense_on: lọc theo trust_level/hash và dấu hiệu Indirect Prompt
Injection / Data Poisoning trong nội dung retrieval.

Sẽ triển khai khung tối thiểu ở Phase 9.
"""

from __future__ import annotations

import hashlib

from security.config import load_security_settings
from security.models import GuardResult, SecurityEvent
from security.patterns import detect_injection_patterns


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def guard_retrieval(documents: list[dict]) -> GuardResult:
    """Luôn quan sát rủi ro retrieval; chỉ lọc khi policy đang được bật."""
    settings = load_security_settings()
    enforce = settings.defense_enabled and settings.retrieval_guard
    accepted: list[dict] = []
    events: list[SecurityEvent] = []

    for document in documents:
        chunk_id = str(document.get("chunk_id", "unknown"))
        content = str(document.get("content", ""))
        try:
            trust_level = float(document.get("trust_level", 0.0))
        except (TypeError, ValueError):
            trust_level = 0.0

        findings: list[tuple[str, str, str]] = []
        if (
            settings.require_managed_trust
            and document.get("trust_managed") is not True
        ):
            findings.append((
                "knowledge_validation",
                "unmanaged_trust_metadata",
                f"Chunk {chunk_id} không có trust do hệ thống quản lý.",
            ))
        if (
            settings.require_allowlisted_source
            and document.get("source_allowlisted") is not True
        ):
            findings.append((
                "knowledge_validation",
                "source_not_allowlisted",
                f"Chunk {chunk_id} đến từ nguồn chưa được phê duyệt.",
            ))
        if trust_level < settings.min_trust_level:
            findings.append((
                "retrieval",
                "minimum_trust_level",
                f"Chunk {chunk_id} có trust level thấp.",
            ))
        expected_hash = document.get("content_hash")
        if (
            settings.verify_content_hash
            and expected_hash
            and expected_hash != _sha256(content)
        ):
            findings.append((
                "knowledge_validation",
                "content_hash_mismatch",
                f"Chunk {chunk_id} có content hash không hợp lệ.",
            ))

        detections = detect_injection_patterns(
            content,
            context="retrieved_content",
        )
        findings.extend(
            (
                "retrieval",
                rule,
                f"Chunk {chunk_id} chứa chỉ dẫn đáng ngờ.",
            )
            for rule in detections
        )
        events.extend(
            SecurityEvent(
                stage=stage,
                rule=rule,
                action="filtered" if enforce else "observed",
                detail=(
                    f"{detail} Đã lọc khỏi retrieval."
                    if enforce
                    else f"{detail} Policy không lọc."
                ),
            )
            for stage, rule, detail in findings
        )
        if enforce and findings:
            continue

        # Không đọc is_poisoned: đây là ground truth chỉ dùng khi đánh giá.
        accepted.append(document)

    return GuardResult(allowed=True, value=accepted, events=events)
