"""Input Guard chấm điểm rủi ro, được dùng trước Planner."""

import re

from security.config import load_security_settings
from security.models import GuardResult, SecurityEvent
from security.patterns import _reuse_detection, detect_injection_patterns
from security.prompt_risk import assess_prompt_risk
from security.semantic_classifier import SemanticClassifier, classify_semantically


_QUOTED_EXAMPLE = re.compile(r'"[^"\r\n]+"|\'[^\'\r\n]+\'|“[^”\r\n]+”|‘[^’\r\n]+’')
_RESEARCH_QUOTE_PREFIX = re.compile(
    r"(?:^(?:explain|analy[sz]e|discuss|translate)\s+(?:why|the\s+(?:phrase|example|attack))\s*:?\s*|"
    r"^the\s+phrase\s+|^(?:the\s+)?(?:paper|study|article)\s+"
    r"(?:describes|discusses|explains|demonstrates)\s*:?\s*|"
    r"^(?:giải\s+thích|phân\s+tích|dịch)\s+(?:vì\s+sao|câu|cụm\s+từ|ví\s+dụ)\s*:?\s*)$",
    re.I,
)


def _assessment_text(user_query: str) -> str:
    """Exclude narrowly framed quoted examples from the scan, not from input.

    A quote or a research label alone grants no exemption. Everything outside
    the quoted span is still scanned, including subsequent imperative clauses.
    This is a bounded heuristic, not a semantic judgment of the whole query.
    """
    def mask_example(match: re.Match[str]) -> str:
        prefix = user_query[:match.start()].strip()
        return " " if _RESEARCH_QUOTE_PREFIX.fullmatch(prefix) else match.group()

    return _QUOTED_EXAMPLE.sub(mask_example, user_query)


@_reuse_detection()
def guard_input(
    user_query: str,
    *,
    semantic_classifier: SemanticClassifier | None = None,
) -> GuardResult:
    """Đánh giá rủi ro tổng hợp của prompt và áp dụng chính sách Off/On.

    ON blocks high risk and unresolved/command medium risk before routing.
    OFF observes the same decisions. Input is never rewritten. The optional
    semantic hook cannot waive deterministic command evidence.
    """

    settings = load_security_settings()
    scan_text = _assessment_text(user_query)
    detections = detect_injection_patterns(scan_text, context="user_input")
    assessment = assess_prompt_risk(scan_text, settings=settings)

    if not detections and not assessment.signals:
        return GuardResult(allowed=True, value=user_query)

    is_medium = (
        settings.prompt_risk_medium_threshold
        <= assessment.score
        < settings.prompt_risk_high_threshold
    )
    semantic_result = None
    if is_medium and settings.semantic_classifier_enabled:
        semantic_result = classify_semantically(
            user_query,
            classifier=semantic_classifier,
            timeout_seconds=settings.semantic_classifier_timeout_seconds,
            fallback_policy=settings.semantic_fallback_policy,
        )
    is_high = assessment.score >= settings.prompt_risk_high_threshold
    command_evidence = bool(detections) or "override" in assessment.signals
    semantic_ok = semantic_result is not None and semantic_result.status == "ok"
    semantic_positive = semantic_ok and semantic_result.positive
    # A real negative can resolve otherwise ambiguous medium risk, but cannot
    # suppress a known command. Missing/failed/disabled providers do not resolve it.
    unresolved_medium = is_medium and not semantic_ok
    should_block = is_high or (is_medium and (command_evidence or semantic_positive or unresolved_medium))
    enforce = settings.defense_enabled and settings.input_guard
    action = "blocked" if enforce and should_block else "allowed" if enforce else "observed"
    decision_reason = (
        "high_risk" if is_high else "medium_command" if is_medium and command_evidence
        else "semantic_positive" if semantic_positive else "medium_unresolved" if unresolved_medium
        else "semantic_negative" if is_medium and semantic_ok else "low_risk"
    )
    semantic_status = semantic_result.status if semantic_result is not None else (
        "disabled" if not settings.semantic_classifier_enabled else "not_evaluated"
    )

    detail = (
        f"Composite prompt risk score={assessment.score:.2f}; "
        f"signals={','.join(assessment.signals) or 'none'}."
        f" decision={decision_reason}; semantic_status={semantic_status};"
    )
    if semantic_result is not None:
        detail += (
            f" semantic_fallback={str(semantic_result.fallback_used).lower()}."
        )

    events: list[SecurityEvent] = []
    event_rules = detections or ["prompt_risk_scoring"]
    if semantic_result is not None:
        event_rules.append("semantic_classifier")
    for rule in event_rules:
        events.append(
            SecurityEvent(
                stage="input",
                attack_type=(
                    "prompt_injection" if semantic_positive and assessment.attack_type == "none"
                    else assessment.attack_type
                ),
                risk_score=assessment.score,
                rule=rule,
                action=action,
                detail=detail,
                mode="on" if settings.defense_enabled else "off",
                metadata={
                    "decision_reason": decision_reason,
                    "semantic_status": semantic_status,
                    "semantic_positive": bool(semantic_positive),
                    "semantic_policy": (
                        settings.semantic_fallback_policy if unresolved_medium
                        else settings.semantic_positive_policy if semantic_positive else None
                    ),
                    "policy_level": (
                        "high" if is_high or (
                            semantic_positive and settings.semantic_positive_policy == "high"
                        ) or (
                            unresolved_medium and settings.semantic_fallback_policy == "high"
                        ) else "medium" if should_block else "allow"
                    ),
                },
            )
        )

    return GuardResult(
        allowed=not (enforce and should_block),
        value=user_query,
        events=events,
    )
