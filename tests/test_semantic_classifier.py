import time

from security.semantic_classifier import classify_semantically


def test_classifier_accepts_injected_structured_result():
    result = classify_semantically(
        "medium prompt",
        classifier=lambda _: {"positive": True, "confidence": 0.91},
    )

    assert result.positive is True
    assert result.confidence == 0.91
    assert result.status == "ok"
    assert result.fallback_used is False


def test_classifier_timeout_uses_configured_fallback():
    def slow(_: str):
        time.sleep(0.1)
        return {"positive": True, "confidence": 1.0}

    started = time.perf_counter()
    result = classify_semantically(
        "medium prompt",
        classifier=slow,
        timeout_seconds=0.01,
        fallback_policy="high",
    )

    assert time.perf_counter() - started < 0.08
    assert result.status == "timeout"
    assert result.fallback_used is True
    assert result.positive is False
    assert result.confidence == 0.0
    assert result.fallback_policy == "high"


def test_classifier_malformed_schema_uses_fallback():
    result = classify_semantically(
        "medium prompt",
        classifier=lambda _: {"label": "yes"},
        fallback_policy="medium",
    )

    assert result.status == "malformed"
    assert result.fallback_used is True
    assert result.positive is False


def test_classifier_exception_is_contained():
    def broken(_: str):
        raise RuntimeError("provider unavailable")

    result = classify_semantically("medium prompt", classifier=broken)

    assert result.status == "error"
    assert result.fallback_used is True


def test_missing_provider_is_unavailable_not_a_negative_classification():
    result = classify_semantically("medium prompt")
    assert result.status == "unavailable"
    assert result.fallback_used is True
    assert result.positive is False
