"""
Sinh trace_id cho mỗi request (uuid4) và cung cấp context manager/decorator
để đo latency quanh mỗi node trong graph (Planner/Research/Analyst/Executor).

Sẽ triển khai ở Phase 8.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
import sys
from time import perf_counter
from uuid import uuid4

from graph.state import AgentState
from tracing.logger import log_step


def new_trace_id() -> str:
    """Sinh trace ID duy nhất cho một request."""
    return str(uuid4())


def _tool_called(agent: str, state: dict) -> str | None:
    if agent != "executor":
        return state.get("tool_called")
    execution = state.get("execution_result") or {}
    request = state.get("execution_request") or {}
    return execution.get("tool") or request.get("tool_name")


def _state_error(agent: str, node_input: dict, output: dict) -> str | None:
    """Lấy lỗi Worker đã bắt nội bộ hoặc lỗi structured của Executor."""
    previous_errors = node_input.get("errors") or []
    output_errors = output.get("errors") or []
    if len(output_errors) > len(previous_errors):
        return str(output_errors[-1])
    if agent == "executor":
        execution = output.get("execution_result") or {}
        if execution.get("status") in {"error", "denied"}:
            return str(execution.get("error") or "Executor failed")
    return None


def _safe_log_step(**kwargs) -> str | None:
    """Không để lỗi telemetry làm hỏng hoặc che lỗi xử lý chính."""
    try:
        log_step(**kwargs)
        return None
    except Exception as exc:
        error_type = type(exc).__name__
        trace_id = str(kwargs.get("trace_id") or "unknown")
        try:
            sys.stderr.write(
                f"[tracing] write failed: {error_type}; trace_id={trace_id}\n"
            )
        except Exception:
            pass
        return error_type


def _record_observed_propagation(agent: str, output: dict) -> None:
    """Ghi agent đã nhận attack khi detector chạy ở monitor-only mode."""
    events = output.get("security_events") or []
    observed_injection = any(
        isinstance(event, dict)
        and event.get("action") == "observed"
        and str(event.get("rule", "")).startswith("prompt_injection_pattern_")
        for event in events
    )
    if not output.get("injection_source") or not observed_injection:
        return
    propagated_to = list(output.get("propagated_to") or [])
    if agent not in propagated_to:
        propagated_to.append(agent)
    output["propagated_to"] = propagated_to


def traced_node(agent: str, node: Callable[[AgentState], AgentState]):
    """Bọc node để sinh trace ID, đo latency và ghi cả success/error."""

    @wraps(node)
    def wrapper(state: AgentState) -> AgentState:
        node_input = dict(state)
        trace_id = str(node_input.get("trace_id") or new_trace_id())
        sequence = int(node_input.get("trace_sequence", 0)) + 1
        node_input["trace_id"] = trace_id
        node_input["trace_sequence"] = sequence
        started = perf_counter()

        try:
            output = dict(node(node_input))
        except Exception as exc:
            latency_ms = (perf_counter() - started) * 1000
            _safe_log_step(
                trace_id=trace_id,
                sequence=sequence,
                agent=agent,
                input_data=node_input,
                output_data={},
                route=node_input.get("route"),
                latency_ms=latency_ms,
                error=f"{type(exc).__name__}: {exc}",
                injection_source=node_input.get("injection_source"),
                target_agent=node_input.get("target_agent"),
                propagated_to=node_input.get("propagated_to"),
                tool_called=_tool_called(agent, node_input),
                final_output_affected=node_input.get("final_output_affected"),
                security_events=node_input.get("security_events"),
            )
            raise

        output["trace_id"] = trace_id
        output["trace_sequence"] = sequence
        _record_observed_propagation(agent, output)
        latency_ms = (perf_counter() - started) * 1000
        logging_error = _safe_log_step(
            trace_id=trace_id,
            sequence=sequence,
            agent=agent,
            input_data=node_input,
            output_data=output,
            route=output.get("route") or node_input.get("route"),
            latency_ms=latency_ms,
            error=_state_error(agent, node_input, output),
            injection_source=output.get("injection_source"),
            target_agent=output.get("target_agent"),
            propagated_to=output.get("propagated_to"),
            tool_called=_tool_called(agent, output),
            final_output_affected=output.get("final_output_affected"),
            security_events=output.get("security_events"),
        )
        if logging_error:
            telemetry_errors = list(output.get("telemetry_errors", []))
            telemetry_errors.append(f"log_step:{logging_error}")
            output["telemetry_failed"] = True
            output["telemetry_errors"] = telemetry_errors
        return output

    return wrapper
