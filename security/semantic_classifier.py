"""Small, provider-agnostic semantic classifier boundary for T05.

The production application can inject an LLM or another semantic model.  The
default implementation is deliberately conservative and returns a negative
classification, while malformed, failing, or slow providers are converted to
an explicit configured fallback result.
"""

from __future__ import annotations

import queue
import threading
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool


ClassifierStatus = Literal["ok", "timeout", "malformed", "error"]
FallbackPolicy = Literal["allow", "medium", "high"]


class SemanticClassifierResult(BaseModel):
    """Validated, provider-neutral result returned to the Input Guard."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    positive: StrictBool
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    status: ClassifierStatus = "ok"
    fallback_used: bool = False


SemanticClassification = SemanticClassifierResult
SemanticClassifier = Callable[[str], Any]


def default_semantic_classifier(_: str) -> SemanticClassifierResult:
    """No-op provider used when an application does not inject one."""

    return SemanticClassifierResult(positive=False, confidence=0.0)


def _fallback_result(
    policy: FallbackPolicy, *, status: ClassifierStatus
) -> SemanticClassifierResult:
    positive = policy == "high"
    confidence = 1.0 if positive else 0.0
    return SemanticClassifierResult(
        positive=positive,
        confidence=confidence,
        status=status,
        fallback_used=True,
    )


def _validate_result(raw: Any) -> SemanticClassifierResult:
    if isinstance(raw, bool):
        return SemanticClassifierResult(positive=raw, confidence=1.0 if raw else 0.0)
    if isinstance(raw, SemanticClassifierResult):
        return raw
    return SemanticClassifierResult.model_validate(raw)


def _invoke_with_timeout(
    classifier: SemanticClassifier,
    text: str,
    timeout_seconds: float,
) -> tuple[str, Any]:
    """Run an arbitrary provider without allowing it to block the caller."""

    result_queue: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=1)

    def worker() -> None:
        try:
            result_queue.put(("ok", classifier(text)))
        except Exception:
            # Provider details are intentionally not returned to telemetry.
            result_queue.put(("error", None))

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    try:
        return result_queue.get(timeout=max(0.001, float(timeout_seconds)))
    except queue.Empty:
        return "timeout", None


def classify_semantically(
    text: str,
    *,
    classifier: SemanticClassifier | None = None,
    timeout_seconds: float = 0.5,
    fallback_policy: FallbackPolicy = "medium",
) -> SemanticClassifierResult:
    """Call an injectable semantic provider with schema and timeout guards."""

    provider = classifier or default_semantic_classifier
    status, raw = _invoke_with_timeout(provider, text, timeout_seconds)
    if status == "timeout":
        return _fallback_result(fallback_policy, status="timeout")
    if status == "error":
        return _fallback_result(fallback_policy, status="error")
    try:
        return _validate_result(raw)
    except Exception:
        return _fallback_result(fallback_policy, status="malformed")


# Friendly aliases for callers and test doubles that use a shorter verb.
run_semantic_classifier = classify_semantically
classify_semantic = classify_semantically

