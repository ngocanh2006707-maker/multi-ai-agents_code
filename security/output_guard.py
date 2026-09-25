"""Final-answer security guard for secrets and prompt leakage."""

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
        r"\b(?:system|developer)\s+(?:prompt|message|instructions?|rules?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:hidden|internal)\s+(?:prompt|instructions?|policy|rules?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:begin|end)[_-](?:system|developer)[_-](?:prompt|instructions?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"(?:prompt|lệnh|chỉ dẫn|hướng dẫn)\s+(?:hệ thống|developer|nội bộ)",
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
    similarity_threshold: float,
) -> list[tuple[str, float]]:
    """Return metadata-only findings without logging matched output text."""

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

    # Structural matches are treated as high-confidence at the configured
    # default threshold. The matched phrase is never put in telemetry.
    if similarity_threshold <= 0.9:
        if any(pattern.search(value) for pattern in PROMPT_LEAK_PATTERNS):
            findings.append(("prompt_structure_leak", 0.9))
    return findings


def guard_output(
    final_answer: str,
    *,
    canary_id: str | None = None,
    canary_fingerprint: str | None = None,
) -> GuardResult:
    """Detect prompt leaks and secrets under the configured Off/On policy."""

    settings = load_security_settings()
    enforce = settings.defense_enabled and settings.output_guard
    original = str(final_answer)
    leak_findings = _prompt_leak_findings(
        original,
        canary_id=canary_id,
        canary_fingerprint=canary_fingerprint,
        similarity_threshold=settings.prompt_leak_similarity_threshold,
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
        # Prompt leak takes precedence over secret redaction.
        sanitized = CANNED_REFUSAL
    elif enforce:
        for pattern in SECRET_PATTERNS:
            sanitized = pattern.sub("[REDACTED]", sanitized)

    return GuardResult(
        allowed=not (prompt_leak_detected and enforce),
        value=sanitized,
        events=events,
    )
