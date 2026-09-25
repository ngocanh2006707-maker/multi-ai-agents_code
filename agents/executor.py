"""
Executor Agent — thực thi tác vụ, CHỈ dùng tool trong allowlist.

Input: execution_request (dict do Planner build, gồm tool_name + params).
Output (ghi vào state.execution_result): dict theo schema mục 6 của spec
(status, tool, result).

Allowlist tool ban đầu (xem tools/registry.py):
  read_dataset, calculate_metrics, calculate_metrics_from_dataset,
  run_security_test, save_test_result

Tuyệt đối KHÔNG cho phép (trừ khi được cấu hình tường minh sau này):
  shell, delete_file, read_secret, send_network_request

Trách nhiệm:
- Kiểm tra tool_name có trong allowlist trước khi gọi (tools/registry.py).
- Trả kết quả có cấu trúc, không silently fail.

Sẽ triển khai ở Phase 6.
"""

from __future__ import annotations

import json
import multiprocessing
import os
from queue import Empty

from pydantic import ValidationError

from agents.executor_schema import ExecutionRequest, ExecutionResult
from graph.state import AgentState
from security.action_gate import ActionGateDecision, evaluate_action_gate
from security.models import SecurityEvent, security_event_to_dict
from tools.registry import ToolNotAllowedError, get_tool


MAX_TOOL_RESULT_BYTES = 100_000


class ToolProcessError(RuntimeError):
    """Tool process thất bại nhưng không đưa message nội bộ ra shared state."""

    def __init__(self, error_type: str):
        super().__init__(error_type)
        self.error_type = error_type


def _tool_worker(result_queue, tool_name: str, params: dict) -> None:
    """Entry point tối thiểu chạy trong process cô lập."""
    try:
        result = get_tool(tool_name)(**params)
        encoded = json.dumps(
            result,
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        if len(encoded) > MAX_TOOL_RESULT_BYTES:
            raise ValueError(
                f"Tool result vượt giới hạn {MAX_TOOL_RESULT_BYTES} bytes"
            )
        result_queue.put({"ok": True, "result": result})
    except Exception as exc:
        result_queue.put({"ok": False, "error_type": type(exc).__name__})


def _tool_timeout_seconds() -> float:
    timeout = float(os.environ.get("EXECUTOR_TOOL_TIMEOUT_SECONDS", "10"))
    if not 0.1 <= timeout <= 120.0:
        raise ValueError("EXECUTOR_TOOL_TIMEOUT_SECONDS phải nằm trong [0.1, 120]")
    return timeout


def _execute_tool_isolated(tool_name: str, params: dict):
    """Chạy tool trong spawn process và chấm dứt khi quá timeout."""
    timeout = _tool_timeout_seconds()
    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue(maxsize=1)
    process = context.Process(
        target=_tool_worker,
        args=(result_queue, tool_name, params),
        daemon=True,
    )
    try:
        process.start()
        try:
            # Đọc queue trước khi join để tránh deadlock do pipe buffer khi
            # tool result gần giới hạn kích thước.
            payload = result_queue.get(timeout=timeout)
        except Empty as exc:
            if process.is_alive():
                process.terminate()
                process.join(2)
                raise TimeoutError("tool_timeout") from exc
            raise ToolProcessError("ToolProcessExitError") from exc
        process.join(2)
        if process.is_alive():
            process.terminate()
            process.join(2)
            raise TimeoutError("tool_did_not_exit")
        if not payload.get("ok"):
            raise ToolProcessError(str(payload.get("error_type") or "ToolError"))
        return payload.get("result")
    finally:
        if process.is_alive():
            process.terminate()
            process.join(2)
        result_queue.close()
        result_queue.join_thread()


def _permission_event(
    tool_name: str,
    allowed: bool,
    *,
    trace_id: str | None = None,
) -> dict:
    event = SecurityEvent(
        stage="tool_permission",
        rule="executor_tool_allowlist",
        action="allowed" if allowed else "blocked",
        detail=(
            f"Tool {tool_name!r} được phép thực thi."
            if allowed
            else f"Tool {tool_name!r} không nằm trong allowlist."
        ),
    )
    return security_event_to_dict(event, trace_id=trace_id)


def _action_gate_event(
    tool_name: str,
    decision: ActionGateDecision,
    *,
    trace_id: str | None = None,
) -> dict:
    event = SecurityEvent(
        stage="tool_permission",
        attack_type=(
            "tool_manipulation"
            if decision.action in {"observed", "blocked"}
            else "none"
        ),
        risk_score=(
            0.9
            if decision.action == "blocked"
            else 0.6
            if decision.action == "observed"
            else 0.0
        ),
        rule=decision.rule,
        action=decision.action,
        detail=(
            f"Action gate decision for tool {tool_name!r}: "
            f"{decision.reason_code}."
        ),
        metadata={
            "destructive": decision.destructive,
            "requires_approval": decision.requires_approval,
        },
    )
    return security_event_to_dict(event, trace_id=trace_id)


def _result(status: str, tool: str, *, result=None, error: str | None = None) -> dict:
    """Tạo execution result đúng schema tại một nơi duy nhất."""
    return ExecutionResult(
        status=status,
        tool=tool or "unknown",
        result=result,
        error=error,
    ).model_dump()


def executor_node(state: AgentState) -> AgentState:
    """Validate request, kiểm tra allowlist rồi gọi đúng một tool."""
    raw_request = state.get("execution_request")
    try:
        request = ExecutionRequest.model_validate(raw_request)
    except ValidationError as exc:
        errors = list(state.get("errors", []))
        errors.append("executor: invalid_request: ValidationError")
        return {
            **state,
            "execution_result": _result(
                "error", "unknown", error="execution_request không hợp lệ"
            ),
            "current_agent": "executor",
            "tool_called": "unknown",
            "errors": errors,
        }

    decision = evaluate_action_gate(
        user_query=state.get("user_query"),
        tool_name=request.tool_name,
        params=request.params,
        params_source=(
            state.get("execution_params_source") or state.get("params_source")
        ),
        approval=(
            state.get("execution_approval")
            if "execution_approval" in state
            else state.get("approval_granted")
        ),
        destructive=state.get("execution_destructive"),
        params_modified=state.get("execution_params_modified"),
        expected_params_digest=state.get("execution_params_digest"),
    )
    security_events = list(state.get("security_events", []))
    gate_event = _action_gate_event(
        request.tool_name,
        decision,
        trace_id=state.get("trace_id"),
    )
    if not decision.allowed:
        security_events.append(gate_event)
        return {
            **state,
            "execution_result": _result(
                "denied",
                request.tool_name,
                error="Action Gate denied the tool request.",
            ),
            "current_agent": "executor",
            "tool_called": request.tool_name,
            "security_events": security_events,
        }

    security_events.append(gate_event)
    try:
        tool = get_tool(request.tool_name)
    except ToolNotAllowedError:
        security_events = list(state.get("security_events", []))
        security_events.append(
            _permission_event(
                request.tool_name,
                False,
                trace_id=state.get("trace_id"),
            )
        )
        return {
            **state,
            "execution_result": _result(
                "denied",
                request.tool_name,
                error="Tool không nằm trong allowlist.",
            ),
            "current_agent": "executor",
            "tool_called": request.tool_name,
            "security_events": security_events,
        }

    security_events.append(
        _permission_event(
            request.tool_name,
            True,
            trace_id=state.get("trace_id"),
        )
    )
    try:
        # Lookup phía trên là permission check; process con lookup lại cùng registry
        # đã khóa trước khi thực thi.
        del tool
        tool_result = _execute_tool_isolated(request.tool_name, request.params)
        return {
            **state,
            "execution_result": _result(
                "success", request.tool_name, result=tool_result
            ),
            "current_agent": "executor",
            "tool_called": request.tool_name,
            "security_events": security_events,
        }
    except Exception as exc:
        errors = list(state.get("errors", []))
        error_type = (
            exc.error_type if isinstance(exc, ToolProcessError) else type(exc).__name__
        )
        errors.append(f"executor: tool_execution_failed: {error_type}")
        return {
            **state,
            "execution_result": _result(
                "error",
                request.tool_name,
                error="Tool thực thi thất bại.",
            ),
            "current_agent": "executor",
            "tool_called": request.tool_name,
            "security_events": security_events,
            "errors": errors,
        }
