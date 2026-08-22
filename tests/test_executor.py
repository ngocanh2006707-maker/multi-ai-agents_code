from unittest.mock import patch

from agents.executor import executor_node
from tools import dataset_tools


def test_executor_runs_allowed_calculate_metrics_tool():
    state = executor_node({
        "execution_request": {
            "tool_name": "calculate_metrics",
            "params": {
                "metric": "attack_success_rate",
                "records": [
                    {"attack_success": True},
                    {"attack_success": False},
                ],
            },
        }
    })
    assert state["current_agent"] == "executor"
    assert state["execution_result"]["status"] == "success"
    assert state["execution_result"]["result"]["value"] == 0.5


def test_executor_denies_tool_outside_allowlist():
    state = executor_node({
        "execution_request": {
            "tool_name": "shell",
            "params": {"command": "whoami"},
        }
    })
    assert state["execution_result"]["status"] == "denied"
    assert state["execution_result"]["tool"] == "shell"
    assert state["tool_called"] == "shell"
    assert state["security_events"][-1]["stage"] == "tool_permission"
    assert state["security_events"][-1]["action"] == "blocked"


def test_executor_rejects_invalid_request():
    state = executor_node({"execution_request": {"params": {}}})
    assert state["execution_result"]["status"] == "error"
    assert state["current_agent"] == "executor"
    assert state["errors"]


def test_executor_converts_tool_exception_to_structured_error():
    state = executor_node({
        "execution_request": {
            "tool_name": "calculate_metrics",
            "params": {"metric": "not_supported", "records": [{"value": 1}]},
        }
    })
    assert state["execution_result"]["status"] == "error"
    assert state["execution_result"]["error"] == "Tool thực thi thất bại."
    assert state["errors"][-1].endswith("ValueError")


def test_executor_cannot_read_file_outside_data(tmp_path, monkeypatch):
    data_root = tmp_path / "data"
    data_root.mkdir()
    outside = tmp_path / "secret.json"
    outside.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(dataset_tools, "DATA_ROOT", data_root.resolve())

    state = executor_node({
        "execution_request": {
            "tool_name": "read_dataset",
            "params": {"path": "../secret.json"},
        }
    })

    assert state["execution_result"]["status"] == "error"
    assert state["execution_result"]["error"] == "execution_request không hợp lệ"
    assert "secret.json" not in state["execution_result"]["error"]


def test_executor_calculates_metric_from_dataset_without_raw_records():
    state = executor_node({
        "execution_request": {
            "tool_name": "calculate_metrics_from_dataset",
            "params": {
                "path": "experiments/phase6_attack_results.jsonl",
                "metric": "attack_success_rate",
            },
        }
    })

    assert state["execution_result"]["status"] == "success"
    result = state["execution_result"]["result"]
    assert result["metric_result"]["value"] == 0.666667
    assert "records" not in result
    assert state["security_events"][-1]["action"] == "allowed"


def test_executor_timeout_is_sanitized_and_structured():
    with patch(
        "agents.executor._execute_tool_isolated",
        side_effect=TimeoutError("private timeout details"),
    ):
        state = executor_node({
            "execution_request": {
                "tool_name": "calculate_metrics",
                "params": {
                    "metric": "attack_success_rate",
                    "records": [{"attack_success": True}],
                },
            }
        })

    assert state["execution_result"]["status"] == "error"
    assert state["execution_result"]["error"] == "Tool thực thi thất bại."
    assert "private timeout details" not in str(state)
    assert state["errors"][-1].endswith("TimeoutError")
