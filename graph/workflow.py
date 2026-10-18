"""
Ghép toàn bộ Agent thành LangGraph StateGraph — Centralized Orchestrator.

Cấu trúc graph mong muốn (xem mục 10 của spec):
    START -> context_boundary -> planner
    planner --(conditional_edges qua route_planner)--> research/analyst/executor/END
    research -> planner
    analyst  -> planner
    executor -> planner

QUAN TRỌNG: Không add_edge tuyến tính cố định
(planner -> research -> analyst -> executor cho MỌI câu hỏi).
Mọi worker luôn add_edge quay VỀ planner, không bao giờ trỏ thẳng sang
worker khác (đúng nguyên tắc mục 21: Worker không giao tiếp trực tiếp).

Graph đã ghép ở phase phát triển 7. Roadmap sửa bảo mật P1–P7 được quản lý
riêng trong SECURITY_FIX_BACKLOG.md.
"""

import inspect
from typing import Callable

from langgraph.graph import END, START, StateGraph
from langgraph.runtime import Runtime

from agents.analyst import analyst_node
from agents.executor import executor_node
from agents.planner import planner_node
from agents.researcher import research_node
from graph.router import route_planner
from graph.state import AgentState, WorkflowInput
from security.context_guard import (
    RuntimeRegistryError,
    WorkflowRuntimeContext,
    context_boundary_node,
    new_workflow_runtime,
)
from security.coordination_guard import RuntimeDecision
from security.action_gate import ExecutionApprovalRequest
from tracing.tracer import traced_node


class UnsupportedExecutionAPI(RuntimeError):
    """Only invoke is supported until each additional API has lifecycle tests."""


_COMMON_WORKER_KEYS = {
    "user_query",
    "errors",
    "security_events",
    "trace_id",
    "trace_sequence",
    "canary_id",
    "canary_fingerprint",
    "telemetry_failed",
    "telemetry_errors",
    "injection_source",
    "target_agent",
    "propagated_to",
    "tool_called",
    "final_output_affected",
}

_COMMON_WORKER_UPDATE_KEYS = {
    "errors",
    "security_events",
    "telemetry_failed",
    "telemetry_errors",
    "injection_source",
    "target_agent",
    "propagated_to",
    "tool_called",
    "final_output_affected",
}

_WORKER_UPDATE_KEYS = {
    "research": _COMMON_WORKER_UPDATE_KEYS | {
        "research_query",
        "retrieved_documents",
        "retrieval_filtered_count",
    },
    "analyst": _COMMON_WORKER_UPDATE_KEYS | {"analysis_result"},
    "executor": _COMMON_WORKER_UPDATE_KEYS | {"execution_result"},
}


def _input_view(state: AgentState, keys: set[str]) -> AgentState:
    return {key: state[key] for key in keys if key in state}


def _worker_update(worker_name: str, output: AgentState) -> AgentState:
    """Whitelist partial updates and bind current_agent to the wrapper identity."""

    allowed = _WORKER_UPDATE_KEYS[worker_name]
    update = {key: output[key] for key in allowed if key in output}
    update["current_agent"] = worker_name
    return update


def _planner_graph_node(
    state: AgentState,
    runtime: Runtime[WorkflowRuntimeContext],
) -> AgentState:
    planner_view = dict(state)
    planner_view.pop("conversation_context", None)
    planner_view.pop("execution_input", None)
    parameters = inspect.signature(planner_node, follow_wrapped=False).parameters
    if "runtime_context" in parameters:
        return planner_node(planner_view, runtime_context=runtime.context)
    # Test/harness stubs from the baseline commonly accept only ``state``.
    return planner_node(planner_view)


def _research_graph_node(
    state: AgentState,
    runtime: Runtime[WorkflowRuntimeContext],
) -> AgentState:
    view = _input_view(
        state,
        _COMMON_WORKER_KEYS | {"research_query", "research_top_k"},
    )
    context = runtime.context
    try:
        if context is None or not context.kb_task:
            raise RuntimeRegistryError("trusted KB task is missing")
        context.registry_snapshot()
    except RuntimeRegistryError:
        return {
            "current_agent": "research", "retrieved_documents": [],
            "errors": [*(state.get("errors") or []), "research: runtime_registry_unavailable"],
            "allowed_use": "none",
            "runtime_decision": RuntimeDecision(
                kind="error", reason_code="runtime_registry_unavailable",
            ).model_dump(),
        }
    task = context.kb_task
    view["user_query"] = task
    view["research_query"] = task
    context.research_dispatched = True
    context.record_checkpoint("retrieval_input", "received")
    output = research_node(view)
    return _worker_update("research", output)


def _analyst_graph_node(
    state: AgentState,
    runtime: Runtime[WorkflowRuntimeContext],
) -> AgentState:
    view = _input_view(
        state,
        _COMMON_WORKER_KEYS | {"retrieved_documents", "kb_task"},
    )
    context = runtime.context
    try:
        if context is None or not context.kb_task:
            raise RuntimeRegistryError("trusted KB task is missing")
        context.record_kb_input("analyst", view.get("retrieved_documents") or [])
        view["kb_task"] = context.kb_task
        view["user_query"] = context.kb_task
    except RuntimeRegistryError:
        return {
            "current_agent": "analyst",
            "analysis_result": {},
            "errors": [*(state.get("errors") or []), "analyst: runtime_registry_unavailable"],
            "allowed_use": "none",
            "runtime_decision": RuntimeDecision(
                kind="error", reason_code="runtime_registry_unavailable",
            ).model_dump(),
        }
    parameters = inspect.signature(analyst_node, follow_wrapped=False).parameters
    output = (
        analyst_node(view, runtime_context=context)
        if "runtime_context" in parameters else analyst_node(view)
    )
    return _worker_update("analyst", output)


def _executor_graph_node(
    state: AgentState, runtime: Runtime[WorkflowRuntimeContext],
) -> AgentState:
    output = executor_node(
        _input_view(
            state,
            _COMMON_WORKER_KEYS | {
                "execution_request",
                "execution_params_source",
                "execution_destructive",
                "execution_params_modified",
                "execution_params_digest",
            },
        ), runtime_context=runtime.context,
    )
    return _worker_update("executor", output)


class WorkflowFacade:
    """Public invoke-only API that owns the trusted per-run runtime context."""

    def __init__(self, compiled_graph, *, approval_callback=None) -> None:
        if approval_callback is not None and not callable(approval_callback):
            raise TypeError("approval_callback must be callable")
        self.__graph = compiled_graph
        self.__approval_callback = approval_callback

    def invoke(self, input_data: dict) -> dict:
        runtime_context = new_workflow_runtime()
        runtime_context.approval_callback = self.__approval_callback
        try:
            result = self.__graph.invoke(input_data, context=runtime_context)
            return {**result, "runtime_telemetry": runtime_context.telemetry_snapshot()}
        finally:
            runtime_context.close()

    def get_graph(self):
        return self.__graph.get_graph()

    @staticmethod
    def _reject(api_name: str) -> None:
        raise UnsupportedExecutionAPI(
            f"{api_name} is not supported by the invoke-only workflow facade"
        )

    def ainvoke(self, *args, **kwargs):
        self._reject("ainvoke")

    def stream(self, *args, **kwargs):
        self._reject("stream")

    def astream(self, *args, **kwargs):
        self._reject("astream")

    def batch(self, *args, **kwargs):
        self._reject("batch")

    def abatch(self, *args, **kwargs):
        self._reject("abatch")

    def batch_as_completed(self, *args, **kwargs):
        self._reject("batch_as_completed")

    def abatch_as_completed(self, *args, **kwargs):
        self._reject("abatch_as_completed")

    def transform(self, *args, **kwargs):
        self._reject("transform")

    def atransform(self, *args, **kwargs):
        self._reject("atransform")

    def stream_events(self, *args, **kwargs):
        self._reject("stream_events")

    def astream_events(self, *args, **kwargs):
        self._reject("astream_events")

    def astream_log(self, *args, **kwargs):
        self._reject("astream_log")


def _compile_workflow():
    """Tạo và compile Centralized Orchestrator workflow.

    Mọi Worker chỉ có một outgoing edge quay về Planner. Planner là node duy
    nhất sử dụng conditional edges để chọn Worker tiếp theo hoặc kết thúc.
    """
    # Chỉ nhận public input đã định nghĩa. Nếu caller gửi kèm plan,
    # current_agent hoặc worker result giả, LangGraph sẽ loại các field đó
    # trước node Planner đầu tiên.
    workflow = StateGraph(
        AgentState,
        context_schema=WorkflowRuntimeContext,
        input_schema=WorkflowInput,
    )

    workflow.add_node(
        "context_boundary",
        traced_node("context_boundary", context_boundary_node),
    )
    workflow.add_node("planner", traced_node("planner", _planner_graph_node))
    workflow.add_node("research", traced_node("research", _research_graph_node))
    workflow.add_node("analyst", traced_node("analyst", _analyst_graph_node))
    workflow.add_node("executor", traced_node("executor", _executor_graph_node))

    workflow.add_edge(START, "context_boundary")
    workflow.add_edge("context_boundary", "planner")
    workflow.add_conditional_edges(
        "planner",
        route_planner,
        {
            "research": "research",
            "analyst": "analyst",
            "executor": "executor",
            "final": END,
        },
    )

    workflow.add_edge("research", "planner")
    workflow.add_edge("analyst", "planner")
    workflow.add_edge("executor", "planner")

    return workflow.compile()


def build_workflow(
    *, approval_callback: Callable[[ExecutionApprovalRequest], bool] | None = None,
) -> WorkflowFacade:
    """Select the unprotected OFF baseline or the protected ON facade."""
    from security.config import load_security_settings
    if not load_security_settings().defense_enabled:
        from graph.baseline import BaselineWorkflow
        return BaselineWorkflow()
    return WorkflowFacade(_compile_workflow(), approval_callback=approval_callback)
