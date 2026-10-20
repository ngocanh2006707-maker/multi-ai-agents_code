"""Kiểm tra ở thời điểm truy xuất và phòng thủ prompt injection gián tiếp."""

from __future__ import annotations

import hashlib
import math
import re

from security.config import load_security_settings
from security.models import GuardResult, SecurityEvent
from security.patterns import _reuse_detection, detect_injection_patterns
from security.prompt_risk import assess_prompt_risk


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _event_id(value: object) -> str:
    """Do not persist arbitrary instructions supplied through document IDs."""
    text = str(value)
    if re.fullmatch(r"[\w./:@-]{1,200}", text) and not detect_injection_patterns(text):
        return text
    return f"sha256:{_sha256(text)}"


@_reuse_detection()
def guard_retrieval(documents: list[dict]) -> GuardResult:
    """Kiểm tra các chunk đã truy xuất mà vẫn giữ hợp đồng Off/On."""
    settings = load_security_settings()
    enforce = settings.defense_enabled and settings.retrieval_guard
    accepted: list[dict] = []
    events: list[SecurityEvent] = []

    for document in documents:
        chunk_id = _event_id(document.get("chunk_id", "unknown"))
        content = str(document.get("content", ""))
        findings: list[tuple[str, str, str]] = []
        try:
            trust_level = float(document.get("trust_level", 0.0))
            valid_trust = math.isfinite(trust_level) and 0.0 <= trust_level <= 1.0
        except (TypeError, ValueError):
            trust_level = 0.0
            valid_trust = False
        if not valid_trust:
            findings.append((
                "knowledge_validation", "invalid_trust_level",
                f"Chunk {chunk_id} có trust level không hợp lệ.",
            ))
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
        if settings.verify_content_hash and not expected_hash:
            findings.append((
                "knowledge_validation", "missing_content_hash",
                f"Chunk {chunk_id} thiếu content hash.",
            ))
        elif settings.verify_content_hash and expected_hash != _sha256(content):
            findings.append((
                "knowledge_validation",
                "content_hash_mismatch",
                f"Chunk {chunk_id} có content hash không hợp lệ.",
            ))

        document_id = document.get("document_id")
        document_id = _event_id(document_id) if document_id is not None else None

        for stage, rule, detail in findings:
            events.append(
                SecurityEvent(
                    stage=stage,
                    attack_type="none",
                    risk_score=0.0,
                    rule=rule,
                    action="filtered" if enforce else "observed",
                    detail=(
                        f"{detail} Đã lọc khỏi retrieval."
                        if enforce
                        else f"{detail} Policy không lọc."
                    ),
                    document_id=document_id,
                    chunk_id=chunk_id,
                )
            )

        injection_filtered = False
        # Scan fields independently: unrelated metadata must not combine into
        # a synthetic high score. These strings are forwarded to Analyst.
        for field in ("content", "title", "source", "document_id", "chunk_id"):
            text = str(document.get(field) or "")
            detections = detect_injection_patterns(text, context="retrieved_content")
            risk = assess_prompt_risk(text, settings=settings, context="retrieved_content")
            # Direct command evidence at medium is sufficient for filtering;
            # retain the measured score instead of inflating it to high.
            filter_field = risk.score >= settings.retrieval_risk_high_threshold or (
                bool(detections) and risk.score >= settings.retrieval_risk_medium_threshold
            )
            injection_filtered = injection_filtered or filter_field
            rules = detections or (["retrieval_prompt_risk_scoring"] if risk.signals else [])
            for rule in rules:
                events.append(
                    SecurityEvent(
                        stage="retrieval",
                        attack_type=("indirect_injection" if detections or risk.attack_type != "none" else "none"),
                        risk_score=risk.score,
                        rule=rule,
                        action="filtered" if enforce and filter_field else "observed",
                        detail=(
                            f"Chunk {chunk_id} có command-context signals "
                            f"trong field {field}, score {risk.score:.2f}."
                        ),
                        document_id=document_id,
                        chunk_id=chunk_id,
                        metadata={"field": field},
                    )
                )

        if enforce and (findings or injection_filtered):
            continue

        # Không đọc is_poisoned: đây là dữ liệu đúng chỉ dùng khi đánh giá.
        accepted.append(document)

    return GuardResult(allowed=True, value=accepted, events=events)
