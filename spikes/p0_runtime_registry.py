"""P0 spike for per-run runtime context and an invoke-only workflow facade.

This module is deliberately isolated from ``graph.workflow``.  It proves the
LangGraph 1.2.x lifecycle needed by P1a without claiming that the production
workflow is already protected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from time import sleep
from typing import Any, NotRequired, TypedDict
from uuid import uuid4

from langgraph.graph import END, START, StateGraph
from langgraph.runtime import Runtime


class RuntimeRegistryError(RuntimeError):
    """The trusted per-run registry is missing, closed, or used by another run."""


class UnsupportedExecutionAPI(RuntimeError):
    """The P0 facade intentionally does not support this execution API."""


@dataclass(frozen=True)
class RegistryEntry:
    context_id: str
    owner_run_id: str
    value: str


@dataclass
class RunRegistry:
    """Small mutable container owned by exactly one facade invocation."""

    run_id: str
    _entries: dict[str, RegistryEntry] = field(default_factory=dict)
    active: bool = True

    def _require_active(self) -> None:
        if not self.active:
            raise RuntimeRegistryError("runtime registry is not active")

    def register(self, value: str) -> str:
        self._require_active()
        context_id = str(uuid4())
        self._entries[context_id] = RegistryEntry(
            context_id=context_id,
            owner_run_id=self.run_id,
            value=value,
        )
        return context_id

    def read(self, context_id: str, *, requester_run_id: str) -> RegistryEntry:
        self._require_active()
        if requester_run_id != self.run_id:
            raise RuntimeRegistryError("runtime registry belongs to another run")
        try:
            entry = self._entries[context_id]
        except KeyError as exc:
            raise RuntimeRegistryError("context ID is not registered") from exc
        if entry.owner_run_id != requester_run_id:
            raise RuntimeRegistryError("context entry belongs to another run")
        return entry

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def close(self) -> None:
        self._entries.clear()
        self.active = False


@dataclass
class RunContext:
    run_id: str
    registry: RunRegistry

    def close(self) -> None:
        self.registry.close()


def _new_run_context() -> RunContext:
    run_id = str(uuid4())
    return RunContext(run_id=run_id, registry=RunRegistry(run_id=run_id))


class SpikeInput(TypedDict):
    marker: str
    fail_after_boundary: NotRequired[bool]
    delay_ms: NotRequired[int]


class SpikeState(SpikeInput, total=False):
    context_id: str
    observed_marker: str
    registry_entries_during_run: int


def _require_context(runtime: Runtime[RunContext]) -> RunContext:
    context = runtime.context
    if context is None:
        raise RuntimeRegistryError("trusted runtime context is missing")
    if context.registry.run_id != context.run_id:
        raise RuntimeRegistryError("runtime context and registry run IDs differ")
    context.registry._require_active()
    return context


def _context_boundary(
    state: SpikeState,
    runtime: Runtime[RunContext],
) -> dict[str, Any]:
    context = _require_context(runtime)
    marker = state.get("marker")
    if not isinstance(marker, str) or not marker:
        raise ValueError("marker must be a non-empty string")
    return {"context_id": context.registry.register(marker)}


def _registry_consumer(
    state: SpikeState,
    runtime: Runtime[RunContext],
) -> dict[str, Any]:
    context = _require_context(runtime)
    delay_ms = int(state.get("delay_ms", 0))
    if delay_ms:
        sleep(max(0, min(delay_ms, 100)) / 1000)
    if state.get("fail_after_boundary"):
        raise RuntimeError("intentional spike failure")
    entry = context.registry.read(
        state["context_id"],
        requester_run_id=context.run_id,
    )
    return {
        "observed_marker": entry.value,
        "registry_entries_during_run": context.registry.entry_count,
    }


def _build_spike_graph():
    graph = StateGraph(
        SpikeState,
        context_schema=RunContext,
        input_schema=SpikeInput,
    )
    graph.add_node("context_boundary", _context_boundary)
    graph.add_node("consumer", _registry_consumer)
    graph.add_edge(START, "context_boundary")
    graph.add_edge("context_boundary", "consumer")
    graph.add_edge("consumer", END)
    return graph.compile()


class InvokeOnlyWorkflowFacade:
    """Own one compiled graph while creating one trusted context per invoke."""

    def __init__(self) -> None:
        self.__graph = _build_spike_graph()

    def invoke(self, input_data: dict[str, Any]) -> dict[str, Any]:
        context = _new_run_context()
        try:
            return self.__graph.invoke(input_data, context=context)
        finally:
            context.close()

    def get_graph(self):
        """Expose only LangGraph's read-only graph representation."""
        return self.__graph.get_graph()

    @staticmethod
    def _reject(api_name: str) -> None:
        raise UnsupportedExecutionAPI(
            f"{api_name} is not supported by the P0 invoke-only facade"
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


def build_registry_spike() -> InvokeOnlyWorkflowFacade:
    return InvokeOnlyWorkflowFacade()

