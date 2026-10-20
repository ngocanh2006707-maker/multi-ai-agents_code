"""Ranh giới classifier ngữ nghĩa nhỏ, không phụ thuộc provider cho T05.

Ứng dụng có thể tiêm provider, nhưng production hiện chưa tích hợp model.
Thiếu provider là unavailable, không phải kết quả phân loại phủ định hợp lệ.
Fallback mô tả lỗi; quyết định enforcement thuộc Input Guard.
"""

from __future__ import annotations

import queue
import threading
from typing import Any, Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool


ClassifierStatus = Literal["ok", "unavailable", "timeout", "malformed", "error"]
FallbackPolicy = Literal["allow", "medium", "high"]


class SemanticClassifierResult(BaseModel):
    """Kết quả đã kiểm tra, không phụ thuộc provider, trả về cho Input Guard."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    positive: StrictBool
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    status: ClassifierStatus = "ok"
    fallback_used: bool = False
    fallback_policy: FallbackPolicy | None = None


SemanticClassification = SemanticClassifierResult
SemanticClassifier = Callable[[str], Any]


def default_semantic_classifier(_: str) -> SemanticClassifierResult:
    """Compatibility entry point: no configured provider is not a negative."""

    return _fallback_result("medium", status="unavailable")


def _fallback_result(
    policy: FallbackPolicy, *, status: ClassifierStatus
) -> SemanticClassifierResult:
    return SemanticClassifierResult(
        positive=False,
        confidence=0.0,
        status=status,
        fallback_used=True,
        fallback_policy=policy,
    )


def _validate_result(raw: Any) -> SemanticClassifierResult:
    if isinstance(raw, bool):
        return SemanticClassifierResult(positive=raw, confidence=1.0 if raw else 0.0)
    result = SemanticClassifierResult.model_validate(
        raw.model_dump() if isinstance(raw, SemanticClassifierResult) else raw
    )
    if result.status != "ok" or result.fallback_used or result.fallback_policy is not None:
        raise ValueError("Provider must return a classification, not a fallback status")
    return result


def _invoke_with_timeout(
    classifier: SemanticClassifier,
    text: str,
    timeout_seconds: float,
) -> tuple[str, Any]:
    """Chạy provider bất kỳ nhưng không cho phép nó chặn caller."""

    result_queue: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=1)

    def worker() -> None:
        try:
            result_queue.put(("ok", classifier(text)))
        except Exception:
            # Cố ý không trả thông tin chi tiết của provider vào telemetry.
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

    if classifier is None or classifier is default_semantic_classifier:
        return _fallback_result(fallback_policy, status="unavailable")
    status, raw = _invoke_with_timeout(classifier, text, timeout_seconds)
    if status == "timeout":
        return _fallback_result(fallback_policy, status="timeout")
    if status == "error":
        return _fallback_result(fallback_policy, status="error")
    try:
        return _validate_result(raw)
    except Exception:
        return _fallback_result(fallback_policy, status="malformed")


# Alias thuận tiện cho caller và test double dùng động từ ngắn hơn.
run_semantic_classifier = classify_semantically
classify_semantic = classify_semantically
