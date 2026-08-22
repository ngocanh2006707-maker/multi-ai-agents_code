import pytest

from tools.metric_tools import (
    calculate_metrics,
    calculate_metrics_from_dataset,
    run_security_test,
)


def test_calculate_attack_success_rate():
    records = [
        {"attack_attempted": True, "attack_success": True},
        {"attack_attempted": True, "attack_success": False},
        {"attack_attempted": False, "attack_success": True},
    ]

    result = calculate_metrics("attack_success_rate", records)

    assert result == {
        "metric": "attack_success_rate",
        "value": 0.5,
        "numerator": 1,
        "denominator": 2,
    }


def test_calculate_metric_accepts_csv_boolean_strings():
    records = [
        {"defense_applied": "1", "defense_success": "true"},
        {"defense_applied": "1", "defense_success": "0"},
    ]
    assert calculate_metrics("defense_success_rate", records)["value"] == 0.5


def test_calculate_metric_uses_all_records_without_eligibility_field():
    records = [{"attack_success": 1}, {"attack_success": 0}]
    assert calculate_metrics("attack_success_rate", records)["denominator"] == 2


def test_calculate_metric_rejects_unknown_metric():
    with pytest.raises(ValueError):
        calculate_metrics("accuracy", [])


def test_calculate_metric_reports_missing_value_field():
    with pytest.raises(ValueError):
        calculate_metrics(
            "attack_success_rate",
            [{"attack_attempted": True}],
        )


@pytest.mark.parametrize(
    ("metric", "expected"),
    [
        ("precision@k", 0.5),
        ("recall@k", 0.75),
        ("mrr", 0.75),
        ("hit_rate", 1.0),
    ],
)
def test_calculate_retrieval_metrics(metric, expected):
    records = [
        {"retrieved_ids": ["a", "x"], "relevant_ids": ["a", "b"]},
        {"retrieved_ids": ["z", "b"], "relevant_ids": ["b"]},
    ]
    assert calculate_metrics(metric, records, k=2)["value"] == expected


def test_calculate_false_positive_and_negative_rates():
    fp = calculate_metrics(
        "false_positive_rate",
        [
            {"actual_negative": True, "false_positive": True},
            {"actual_negative": True, "false_positive": False},
        ],
    )
    fn = calculate_metrics(
        "false_negative_rate",
        [
            {"actual_positive": True, "false_negative": False},
            {"actual_positive": True, "false_negative": True},
        ],
    )
    assert fp["value"] == 0.5
    assert fn["value"] == 0.5


def test_retrieval_metric_deduplicates_retrieved_ids():
    result = calculate_metrics(
        "recall@k",
        [{"retrieved_ids": ["a", "a"], "relevant_ids": ["a"]}],
        k=2,
    )
    assert result["value"] == 1.0


def test_metric_rejects_empty_records_and_empty_denominator():
    with pytest.raises(ValueError, match="records không được rỗng"):
        calculate_metrics("attack_success_rate", [])
    with pytest.raises(ValueError, match="Không có record đủ điều kiện"):
        calculate_metrics(
            "attack_success_rate",
            [{"attack_attempted": False, "attack_success": False}],
        )


def test_metric_rejects_partial_eligibility_schema():
    with pytest.raises(ValueError, match="phải xuất hiện trong mọi record"):
        calculate_metrics(
            "attack_success_rate",
            [
                {"attack_attempted": True, "attack_success": True},
                {"attack_success": False},
            ],
        )


def test_retrieval_metric_validates_identifier_lists():
    with pytest.raises(TypeError, match=r"list\[str\]"):
        calculate_metrics(
            "recall@k",
            [{"retrieved_ids": "abc", "relevant_ids": ["a"]}],
            k=2,
        )


def test_calculate_metrics_from_dataset_returns_only_aggregate():
    result = calculate_metrics_from_dataset(
        "experiments/phase6_attack_results.jsonl",
        "attack_success_rate",
    )
    assert result["record_count"] == 3
    assert result["metric_result"]["value"] == 0.666667
    assert "records" not in result


def test_run_security_test_only_dispatches_metrics():
    result = run_security_test({
        "metrics": ["attack_success_rate"],
        "records": [
            {"attack_attempted": True, "attack_success": True},
            {"attack_attempted": True, "attack_success": False},
        ],
    })
    assert result["status"] == "completed"
    assert result["metrics"][0]["value"] == 0.5

    with pytest.raises(ValueError, match="field không hợp lệ"):
        run_security_test({"script": "whoami"})
