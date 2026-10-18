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
from typing import Any
from uuid import uuid4

from langgraph.runtime import Runtime

from graph.state import AgentState
from security.context_guard import WorkflowRuntimeContext
from security.coordination_guard import RuntimeDecision
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
    """Return a metadata-only error signal without exception payload text."""
    previous_errors = node_input.get("errors") or []
    output_errors = output.get("errors") or []
    if len(output_errors) > len(previous_errors):
        return f"{agent}:reported_error"
    if agent == "executor":
        execution = output.get("execution_result") or {}
        if execution.get("status") == "error":
            return "executor:reported_error"
    return None


def trace_state_view(state: dict[str, Any]) -> dict[str, Any]:
    """Build the metadata allowlist; never copy free-form state text."""
    envelopes = [
        {
            key: envelope.get(key)
            for key in ("result_id", "producer", "channel", "source_class", "payload_key")
            if key in envelope
        }
        for envelope in (state.get("result_envelopes") or [])
        if isinstance(envelope, dict)
    ]
    decision = state.get("runtime_decision")
    safe_decision = None
    if isinstance(decision, dict):
        safe_decision = {
            key: decision.get(key)
            for key in ("kind", "reason_code", "omitted_result_ids")
            if key in decision
        }
    view: dict[str, Any] = {
        "state_keys": sorted(str(key) for key in state),
        "query_characters": len(str(state.get("user_query") or "")),
        "has_context": bool(state.get("has_context")),
        "context_message_count": int(state.get("context_message_count", 0) or 0),
        "context_character_count": int(
            state.get("context_character_count", 0) or 0
        ),
        "context_metadata_discarded": int(
            state.get("context_metadata_discarded", 0) or 0
        ),
        "allowed_use": str(state.get("allowed_use") or "none"),
        "route": state.get("route"),
        "plan_length": len(state.get("plan") or []),
        "current_agent": state.get("current_agent"),
        "next_agent": state.get("next_agent"),
        "retrieved_document_count": len(state.get("retrieved_documents") or []),
        "has_analysis_result": bool(state.get("analysis_result")),
        "has_execution_result": bool(state.get("execution_result")),
        "has_final_answer": bool(state.get("final_answer")),
        "error_count": len(state.get("errors") or []),
        "security_event_count": len(state.get("security_events") or []),
        "result_envelopes": envelopes,
        "runtime_decision": safe_decision,
        "runtime_reason_codes": [
            str(code) for code in (state.get("runtime_reason_codes") or [])
        ],
        "caller_quote_message_count": int(
            state.get("caller_quote_message_count", 0) or 0
        ),
        "caller_quote_character_count": int(
            state.get("caller_quote_character_count", 0) or 0
        ),
        "caller_quote_removed_character_count": int(
            state.get("caller_quote_removed_character_count", 0) or 0
        ),
        "caller_quote_truncated": bool(state.get("caller_quote_truncated")),
    }
    for key in (
        "context_digest",
        "context_boundary_error",
        "domain_status",
        "source_scope",
        "scope_certainty",
        "scope_reason_code",
        "trace_id",
        "trace_sequence",
    ):
        value = state.get(key)
        if value is not None:
            view[key] = value
    return view


def _security_event_view(events: list[dict] | None) -> list[dict[str, Any]]:
    """Keep event enums and IDs while dropping detail and arbitrary metadata."""
    allowed = {
        "stage",
        "attack_type",
        "risk_score",
        "rule",
        "action",
        "trace_id",
        "document_id",
        "chunk_id",
        "mode",
    }
    result = []
    for event in events or []:
        if not isinstance(event, dict):
            continue
        view = {key: event.get(key) for key in allowed if key in event}
        metadata = event.get("metadata")
        if isinstance(metadata, dict):
            for key in ("part", "checkpoint"):
                if key in metadata:
                    view[key] = metadata[key]
        result.append(view)
    return result


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


def traced_node(agent: str, node: Callable):
    """Bọc node để sinh trace ID, đo latency và ghi cả success/error."""

    @wraps(node)
    def wrapper(
        state: AgentState,
        runtime: Runtime[Any] | None = None,
    ) -> AgentState:
        node_input = dict(state)
        trace_id = str(node_input.get("trace_id") or new_trace_id())
        sequence = int(node_input.get("trace_sequence", 0)) + 1
        node_input["trace_id"] = trace_id
        node_input["trace_sequence"] = sequence
        started = perf_counter()
        context = runtime.context if runtime is not None else None
        if not isinstance(context, WorkflowRuntimeContext):
            context = None
        checkpoint_offset = len(context.checkpoints) if context is not None else 0
        call_offset = len(context.model_calls) if context is not None else 0

        def output_view(output):
            view = trace_state_view(output)
            if context is not None:
                telemetry = context.telemetry_snapshot()
                # These are node-local deltas; the summary is a snapshot and
                # must not be summed across repeated Planner visits.
                view["checkpoints"] = telemetry["checkpoints"][checkpoint_offset:]
                view["model_calls"] = telemetry["model_calls"][call_offset:]
                view["model_call_summary"] = telemetry["summary"]
                view["run_id"] = telemetry["run_id"]
            return view

        try:
            output = dict(
                node(node_input, runtime) if runtime is not None else node(node_input)
            )
        except Exception as exc:
            latency_ms = (perf_counter() - started) * 1000
            _safe_log_step(
                trace_id=trace_id,
                sequence=sequence,
                agent=agent,
                input_data=trace_state_view(node_input),
                output_data=output_view({}),
                route=node_input.get("route"),
                latency_ms=latency_ms,
                error=type(exc).__name__,
                injection_source=node_input.get("injection_source"),
                target_agent=node_input.get("target_agent"),
                propagated_to=node_input.get("propagated_to"),
                tool_called=_tool_called(agent, node_input),
                final_output_affected=node_input.get("final_output_affected"),
                security_events=_security_event_view(
                    node_input.get("security_events")
                ),
            )
            raise

        output["trace_id"] = trace_id
        output["trace_sequence"] = sequence
        if (
            context is not None
            and isinstance(output.get("runtime_decision"), dict)
            and output["runtime_decision"] != node_input.get("runtime_decision")
        ):
            decision = RuntimeDecision.model_validate(output["runtime_decision"])
            context.record_checkpoint("runtime_decision", "policy", verdict=decision.kind)
        latency_ms = (perf_counter() - started) * 1000
        logging_error = _safe_log_step(
            trace_id=trace_id,
            sequence=sequence,
            agent=agent,
            input_data=trace_state_view(node_input),
            output_data=output_view(output),
            route=output.get("route") or node_input.get("route"),
            latency_ms=latency_ms,
            error=_state_error(agent, node_input, output),
            injection_source=output.get("injection_source"),
            target_agent=output.get("target_agent"),
            propagated_to=output.get("propagated_to"),
            tool_called=_tool_called(agent, output),
            final_output_affected=output.get("final_output_affected"),
            security_events=_security_event_view(output.get("security_events")),
        )
        if logging_error:
            telemetry_errors = list(output.get("telemetry_errors", []))
            telemetry_errors.append(f"log_step:{logging_error}")
            output["telemetry_failed"] = True
            output["telemetry_errors"] = telemetry_errors
        return output

    return wrapper
