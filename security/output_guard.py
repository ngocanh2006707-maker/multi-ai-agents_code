"""Output Guard bảo vệ câu trả lời cuối khỏi secret và rò rỉ prompt."""

from __future__ import annotations

import re

from security.config import load_security_settings
from security.models import GuardResult, SecurityEvent


SECRET_PATTERNS = (
    re.compile(r"\bAIza[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._-]{16,}\b", re.IGNORECASE),
)

CANNED_REFUSAL = "I can't provide hidden system or developer instructions."

PROMPT_LEAK_PATTERNS = (
    re.compile(
        r"(?:^|\n)\s*(?:here\s+(?:is|are)|(?:my|our|the)\s+(?:actual|hidden|internal))\s+"
        r"(?:the\s+)?(?:system|developer|hidden|internal)\s+"
        r"(?:prompt|message|instructions?|policy|rules?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:system|developer|hidden|internal)\s+(?:prompt|instructions?|policy|rules?)\s+"
        r"(?:(?:is|was|has\s+been)\s+)?(?:leaked|disclosed|revealed)\b|"
        r"\b(?:my|our)\s+(?:system|developer)\s+(?:prompt|instructions?)\s*(?:is|says|reads)\s*:",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:^|\n)\s*<?begin[_-](system|developer)[_-](prompt|instructions?)>?\s*\n"
        r"[^\n]+(?:\n[^\n]+)*?\n\s*<?end[_-]\1[_-]\2>?",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:^|\n)\s*(?:đây\s+là|sau\s+đây\s+là)\s+"
        r"(?:prompt|lệnh|chỉ\s+dẫn|hướng\s+dẫn)\s+(?:hệ\s+thống|developer|nội\s+bộ)\b",
        re.IGNORECASE,
    ),
)


def _is_canned_refusal(value: str) -> bool:
    return " ".join(value.split()).casefold() == CANNED_REFUSAL.casefold()


def _prompt_leak_findings(
    value: str,
    *,
    canary_id: str | None,
    canary_fingerprint: str | None,
    structure_check_enabled: bool,
) -> list[tuple[str, float]]:
    """Trả về phát hiện chỉ gồm metadata mà không ghi text khớp vào log."""

    if _is_canned_refusal(value):
        return []

    lowered = value.casefold()
    findings: list[tuple[str, float]] = []
    marker = str(canary_id or "").strip().casefold()
    if marker and marker in lowered:
        findings.append(("prompt_canary_leak", 1.0))

    fingerprint = str(canary_fingerprint or "").strip().casefold()
    if fingerprint and fingerprint in lowered:
        findings.append(("prompt_fingerprint_leak", 1.0))

    # This is a disclosure-frame heuristic, not prompt similarity or proof that
    # the claimed content matches a real system prompt. Mere terms do not match.
    if structure_check_enabled:
        if any(pattern.search(value) for pattern in PROMPT_LEAK_PATTERNS):
            findings.append(("prompt_structure_leak", 0.9))
    return findings


def guard_output(
    final_answer: str,
    *,
    canary_id: str | None = None,
    canary_fingerprint: str | None = None,
) -> GuardResult:
    """Phát hiện rò rỉ prompt và secret theo chính sách Off/On đã cấu hình."""

    settings = load_security_settings()
    enforce = settings.defense_enabled and settings.output_guard
    original = str(final_answer)
    leak_findings = _prompt_leak_findings(
        original,
        canary_id=canary_id,
        canary_fingerprint=canary_fingerprint,
        structure_check_enabled=settings.prompt_structure_check_enabled,
    )
    prompt_leak_detected = bool(leak_findings)
    sanitized = original
    events: list[SecurityEvent] = []

    for rule, score in leak_findings:
        events.append(
            SecurityEvent(
                stage="output",
                attack_type="prompt_exfiltration",
                risk_score=score,
                rule=rule,
                action="blocked" if enforce else "observed",
                detail="Prompt leak indicator detected in final output.",
                metadata={"detector": "prompt_leak"},
            )
        )

    secret_matches: list[tuple[int, int]] = []
    for index, pattern in enumerate(SECRET_PATTERNS, start=1):
        count = len(pattern.findall(original))
        if count:
            secret_matches.append((index, count))

    for index, count in secret_matches:
        action = (
            "blocked"
            if prompt_leak_detected and enforce
            else "redacted"
            if enforce
            else "observed"
        )
        events.append(
            SecurityEvent(
                stage="output",
                rule=f"secret_pattern_{index}",
                action=action,
                detail=(
                    f"Redacted {count} sensitive value(s) from final output."
                    if action == "redacted"
                    else f"Detected {count} sensitive value(s) in final output."
                ),
            )
        )

    if prompt_leak_detected and enforce:
        # Rò rỉ prompt được ưu tiên xử lý trước việc che giấu secret.
        sanitized = CANNED_REFUSAL
    elif enforce:
        for pattern in SECRET_PATTERNS:
            sanitized = pattern.sub("[REDACTED]", sanitized)

    return GuardResult(
        allowed=not (prompt_leak_detected and enforce),
        value=sanitized,
        events=events,
    )
