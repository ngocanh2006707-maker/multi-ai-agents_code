"""
Tool: calculate_metrics, calculate_metrics_from_dataset, run_security_test.

calculate_metrics: tính các metric mục 16 (Retrieval / Prompt Injection /
Data Poisoning / Defense) từ kết quả thử nghiệm đã có.

Sẽ triển khai ở Phase 6 (khung tối thiểu), mở rộng đầy đủ ở Phase 9.
"""

from __future__ import annotations

from typing import Any

from tools.dataset_tools import _load_dataset


_METRIC_FIELDS: dict[str, tuple[str, str | None]] = {
    "attack_success_rate": ("attack_success", "attack_attempted"),
    "defense_success_rate": ("defense_success", "defense_applied"),
    "injection_detection_rate": ("injection_detected", "injection_present"),
    "propagation_rate": ("injection_propagated", "injection_present"),
    "tool_misuse_rate": ("tool_misused", "attack_attempted"),
    "poison_retrieval_rate": ("poison_retrieved", "retrieval_performed"),
    "poison_influence_rate": ("poison_influenced", "poison_retrieved"),
    "poison_acceptance_rate": ("poison_accepted", "poison_retrieved"),
    "false_positive_rate": ("false_positive", "actual_negative"),
    "false_negative_rate": ("false_negative", "actual_positive"),
}

_RETRIEVAL_METRICS = {"recall_at_k", "precision_at_k", "mrr", "hit_rate"}
MAX_METRIC_RECORDS = 10_000


def _as_bool(value: Any) -> bool:
    """Chuẩn hóa giá trị boolean thường gặp trong CSV/JSON."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y"}:
            return True
        if normalized in {"0", "false", "no", "n", ""}:
            return False
    raise ValueError(f"Không thể chuyển thành boolean: {value!r}")


def _calculate_retrieval_metric(
    metric: str, records: list[dict], k: int | None
) -> dict[str, Any]:
    if k is not None and k <= 0:
        raise ValueError("k phải > 0")
    if metric in {"precision_at_k", "recall_at_k"} and k is None:
        raise ValueError(f"Metric {metric} bắt buộc phải có k")
    scores: list[float] = []
    for index, record in enumerate(records):
        if "retrieved_ids" not in record or "relevant_ids" not in record:
            raise ValueError(
                f"Record tại index {index} cần retrieved_ids và relevant_ids"
            )
        retrieved_value = record["retrieved_ids"]
        relevant_value = record["relevant_ids"]
        if not isinstance(retrieved_value, list) or not all(
            isinstance(item, str) for item in retrieved_value
        ):
            raise TypeError(f"retrieved_ids tại index {index} phải là list[str]")
        if not isinstance(relevant_value, list) or not all(
            isinstance(item, str) for item in relevant_value
        ):
            raise TypeError(f"relevant_ids tại index {index} phải là list[str]")

        # Một tài liệu chỉ được tính một lần nhưng vẫn giữ thứ hạng đầu tiên.
        retrieved = list(dict.fromkeys(retrieved_value))
        relevant = set(relevant_value)
        top = retrieved[:k] if k is not None else retrieved
        relevant_retrieved = sum(item in relevant for item in top)

        if metric == "precision_at_k":
            score = relevant_retrieved / len(top) if top else 0.0
        elif metric == "recall_at_k":
            score = relevant_retrieved / len(relevant) if relevant else 0.0
        elif metric == "hit_rate":
            score = float(relevant_retrieved > 0)
        else:
            score = next(
                (1.0 / rank for rank, item in enumerate(top, 1) if item in relevant),
                0.0,
            )
        scores.append(score)

    denominator = len(scores)
    numerator = sum(scores)
    return {
        "metric": metric,
        "value": round(numerator / denominator if denominator else 0.0, 6),
        "numerator": round(numerator, 6),
        "denominator": denominator,
        "k": k,
    }


def calculate_metrics(
    metric: str, records: list[dict], k: int | None = None
) -> dict[str, Any]:
    """Tính một security rate từ danh sách bản ghi thí nghiệm.

    Nếu field điều kiện không xuất hiện trong toàn bộ dataset, mọi record được
    xem là đủ điều kiện. Nếu field xuất hiện, chỉ record có giá trị true được
    đưa vào mẫu số.
    """
    return _calculate_metrics(metric, records, k, record_limit=MAX_METRIC_RECORDS)


def _calculate_metrics(metric, records, k=None, *, record_limit=None):
    """Shared arithmetic; the protected public tool supplies its record cap."""
    metric_name = str(metric).strip().lower().replace("@", "_at_").replace("-", "_")
    if not isinstance(records, list) or not all(
        isinstance(record, dict) for record in records
    ):
        raise TypeError("records phải là list[dict]")
    if not records:
        raise ValueError("records không được rỗng")
    if record_limit is not None and len(records) > record_limit:
        raise ValueError(f"records vượt giới hạn {record_limit} items")
    if metric_name in _RETRIEVAL_METRICS:
        return _calculate_retrieval_metric(metric_name, records, k)
    if metric_name not in _METRIC_FIELDS:
        raise ValueError(
            f"Metric không được hỗ trợ: {metric_name!r}. "
            f"Hợp lệ: {sorted(set(_METRIC_FIELDS) | _RETRIEVAL_METRICS)}"
        )
    value_field, eligibility_field = _METRIC_FIELDS[metric_name]
    eligibility_presence = [
        bool(eligibility_field) and eligibility_field in record
        for record in records
    ]
    if any(eligibility_presence) and not all(eligibility_presence):
        raise ValueError(
            f"Field điều kiện {eligibility_field!r} phải xuất hiện trong mọi record"
        )
    use_eligibility = bool(eligibility_field) and all(eligibility_presence)

    eligible_records: list[tuple[int, dict]] = []
    for original_index, record in enumerate(records):
        if use_eligibility and not _as_bool(record.get(eligibility_field, False)):
            continue
        eligible_records.append((original_index, record))

    if not eligible_records:
        raise ValueError("Không có record đủ điều kiện để tính metric")

    numerator = 0
    for original_index, record in eligible_records:
        if value_field not in record:
            raise ValueError(
                f"Record đủ điều kiện tại index {original_index} "
                f"thiếu field {value_field!r}"
            )
        numerator += int(_as_bool(record[value_field]))

    denominator = len(eligible_records)
    value = numerator / denominator if denominator else 0.0
    return {
        "metric": metric_name,
        "value": round(value, 6),
        "numerator": numerator,
        "denominator": denominator,
    }


def calculate_metrics_from_dataset(
    path: str,
    metric: str,
    k: int | None = None,
) -> dict[str, Any]:
    """Đọc dataset và tính metric nội bộ mà không trả raw records ra state."""
    resolved, extension, records = _load_dataset(path)
    if not all(isinstance(record, dict) for record in records):
        raise TypeError("Dataset dùng tính metric phải chứa các object records")
    metric_result = calculate_metrics(metric=metric, records=records, k=k)
    return {
        "dataset": resolved.name,
        "format": extension.removeprefix("."),
        "record_count": len(records),
        "metric_result": metric_result,
    }


def run_security_test(config: dict) -> dict[str, Any]:
    """Chạy một tập metric thuần túy; tuyệt đối không chạy script/shell tùy ý."""
    if not isinstance(config, dict):
        raise TypeError("config phải là dict")
    allowed_keys = {"metrics", "records", "k"}
    unknown = set(config) - allowed_keys
    if unknown:
        raise ValueError(f"Security test config có field không hợp lệ: {sorted(unknown)}")

    metrics = config.get("metrics")
    records = config.get("records")
    k = config.get("k")
    if isinstance(metrics, str):
        metrics = [metrics]
    if not isinstance(metrics, list) or not metrics or not all(
        isinstance(metric, str) and metric.strip() for metric in metrics
    ):
        raise ValueError("config.metrics phải là list[str] không rỗng")
    if len(metrics) > 20:
        raise ValueError("config.metrics vượt giới hạn 20 items")

    results = [
        calculate_metrics(metric=metric, records=records, k=k)
        for metric in metrics
    ]
    return {
        "status": "completed",
        "metric_count": len(results),
        "metrics": results,
    }
