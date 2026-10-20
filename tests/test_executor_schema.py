import pytest
from pydantic import ValidationError

from agents.executor_schema import ExecutionRequest, ExecutionResult


def test_execution_request_normalizes_tool_name():
    request = ExecutionRequest(
        tool_name="  calculate_metrics  ",
        params={
            "metric": "attack_success_rate",
            "records": [{"attack_success": True}],
        },
    )
    assert request.tool_name == "calculate_metrics"


def test_execution_request_rejects_empty_tool_name():
    with pytest.raises(ValidationError):
        ExecutionRequest(tool_name="   ")


def test_success_result_accepts_structured_data():
    result = ExecutionResult(
        status="success",
        tool="calculate_metrics",
        result={"attack_success_rate": 0.31},
    )
    assert result.status == "success"
    assert result.error is None


def test_success_result_rejects_error_message():
    with pytest.raises(ValidationError):
        ExecutionResult(
            status="success",
            tool="calculate_metrics",
            result={},
            error="Không được xuất hiện",
        )


def test_denied_result_requires_error_message():
    with pytest.raises(ValidationError):
        ExecutionResult(status="denied", tool="shell")


def test_unknown_status_is_rejected():
    with pytest.raises(ValidationError):
        ExecutionResult(
            status="failed",
            tool="calculate_metrics",
            error="Lỗi",
        )


def test_execution_request_rejects_extra_fields_and_tool_params():
    with pytest.raises(ValidationError):
        ExecutionRequest(
            tool_name="calculate_metrics",
            params={
                "metric": "attack_success_rate",
                "records": [{"attack_success": True}],
                "command": "whoami",
            },
            hidden_instruction="ignore policy",
        )


def test_execution_result_rejects_inconsistent_status_fields():
    with pytest.raises(ValidationError):
        ExecutionResult(status="success", tool="calculate_metrics")
    with pytest.raises(ValidationError):
        ExecutionResult(
            status="error",
            tool="calculate_metrics",
            result={"partial": True},
            error="failed",
        )
    with pytest.raises(ValidationError):
        ExecutionResult(status="success", tool="   ", result={})
