"""Risk-scored user input guard used before the Planner."""

from security.config import load_security_settings
from security.models import GuardResult, SecurityEvent
from security.patterns import detect_injection_patterns
from security.prompt_risk import assess_prompt_risk
from security.semantic_classifier import SemanticClassifier, classify_semantically


def guard_input(
    user_query: str,
    *,
    semantic_classifier: SemanticClassifier | None = None,
) -> GuardResult:
    """Assess composite prompt risk and apply the Off/On policy.

    Medium risk remains observable in Defense On until a real route restriction
    exists in Planner/state.  The input value is never rewritten by scoring.
    """

    settings = load_security_settings()
    detections = detect_injection_patterns(user_query)
    assessment = assess_prompt_risk(user_query, settings=settings)

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
        if semantic_result.positive and settings.semantic_positive_policy == "high":
            assessment = assessment.model_copy(
                update={
                    "score": settings.prompt_risk_high_threshold,
                    "attack_type": (
                        assessment.attack_type
                        if assessment.attack_type != "none"
                        else "prompt_injection"
                    ),
                }
            )

    is_high = assessment.score >= settings.prompt_risk_high_threshold
    is_medium = (
        settings.prompt_risk_medium_threshold
        <= assessment.score
        < settings.prompt_risk_high_threshold
    )
    enforce = settings.defense_enabled and settings.input_guard
    if is_high:
        action = "blocked" if enforce else "observed"
    elif is_medium:
        # No real route restriction exists yet, so medium risk is observed.
        action = "observed"
    else:
        action = "allowed" if enforce else "observed"

    detail = (
        f"Composite prompt risk score={assessment.score:.2f}; "
        f"signals={','.join(assessment.signals) or 'none'}."
    )
    if semantic_result is not None:
        detail += (
            f" semantic_status={semantic_result.status};"
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
                attack_type=assessment.attack_type,
                risk_score=assessment.score,
                rule=rule,
                action=action,
                detail=detail,
            )
        )

    return GuardResult(
        allowed=not (enforce and is_high),
        value=user_query,
        events=events,
    )
