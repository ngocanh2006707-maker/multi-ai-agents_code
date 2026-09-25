"""Retrieval-time validation and indirect prompt-injection defense."""

from __future__ import annotations

import hashlib

from security.config import load_security_settings
from security.models import GuardResult, SecurityEvent
from security.patterns import detect_injection_patterns
from security.prompt_risk import assess_prompt_risk


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def guard_retrieval(documents: list[dict]) -> GuardResult:
    """Validate retrieved chunks while preserving the Off/On contract."""
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

        risk = assess_prompt_risk(
            content,
            settings=settings,
            context="retrieved_content",
        )
        risk_score = risk.score
        # A canonicalized command pattern is high-confidence indirect
        # injection evidence even when its composite score is only medium.
        high_risk = risk_score >= settings.retrieval_risk_high_threshold
        if detections and risk_score >= settings.retrieval_risk_medium_threshold:
            high_risk = True
            risk_score = max(risk_score, settings.retrieval_risk_high_threshold)

        document_id = document.get("document_id")
        document_id = str(document_id) if document_id is not None else None

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

        if detections:
            for rule in detections:
                events.append(
                    SecurityEvent(
                        stage="retrieval",
                        attack_type="indirect_injection",
                        risk_score=risk_score,
                        rule=rule,
                        action="filtered" if enforce and high_risk else "observed",
                        detail=(
                            f"Chunk {chunk_id} chứa command injection có score "
                            f"{risk_score:.2f}."
                        ),
                        document_id=document_id,
                        chunk_id=chunk_id,
                    )
                )
        elif risk.signals:
            events.append(
                SecurityEvent(
                    stage="retrieval",
                    attack_type="indirect_injection",
                    risk_score=risk_score,
                    rule="retrieval_prompt_risk_scoring",
                    action="filtered" if enforce and high_risk else "observed",
                    detail=(
                        f"Chunk {chunk_id} có command-context signals="
                        f"{','.join(risk.signals)} với score {risk_score:.2f}."
                    ),
                    document_id=document_id,
                    chunk_id=chunk_id,
                )
            )

        if enforce and (findings or high_risk):
            continue

        # Không đọc is_poisoned: đây là ground truth chỉ dùng khi đánh giá.
        accepted.append(document)

    return GuardResult(allowed=True, value=accepted, events=events)
