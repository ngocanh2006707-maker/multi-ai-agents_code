"""Acceptance tests for the isolated P0 runtime-registry spike."""

from concurrent.futures import ThreadPoolExecutor

import pytest

import spikes.p0_runtime_registry as spike


def _capture_contexts(monkeypatch):
    contexts = []
    original_factory = spike._new_run_context

    def factory():
        context = original_factory()
        contexts.append(context)
        return context

    monkeypatch.setattr(spike, "_new_run_context", factory)
    return contexts


def test_invoke_creates_and_cleans_one_registry(monkeypatch):
    contexts = _capture_contexts(monkeypatch)

    result = spike.build_registry_spike().invoke({"marker": "run-a"})

    assert result["observed_marker"] == "run-a"
    assert result["registry_entries_during_run"] == 1
    assert len(contexts) == 1
    assert contexts[0].registry.active is False
    assert contexts[0].registry.entry_count == 0


def test_cleanup_runs_when_a_node_raises(monkeypatch):
    contexts = _capture_contexts(monkeypatch)
    facade = spike.build_registry_spike()

    with pytest.raises(RuntimeError, match="intentional spike failure"):
        facade.invoke({"marker": "run-error", "fail_after_boundary": True})

    assert len(contexts) == 1
    assert contexts[0].registry.active is False
    assert contexts[0].registry.entry_count == 0


def test_missing_runtime_context_fails_closed():
    raw_graph = spike._build_spike_graph()

    with pytest.raises(spike.RuntimeRegistryError, match="context is missing"):
        raw_graph.invoke({"marker": "no-context"})


def test_registry_rejects_wrong_run_and_closed_access():
    owner = spike._new_run_context()
    other = spike._new_run_context()
    context_id = owner.registry.register("owned")

    with pytest.raises(spike.RuntimeRegistryError, match="another run"):
        owner.registry.read(context_id, requester_run_id=other.run_id)

    owner.close()
    with pytest.raises(spike.RuntimeRegistryError, match="not active"):
        owner.registry.read(context_id, requester_run_id=owner.run_id)


def test_two_concurrent_invokes_on_one_facade_are_isolated(monkeypatch):
    contexts = _capture_contexts(monkeypatch)
    facade = spike.build_registry_spike()

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(
                facade.invoke,
                {"marker": marker, "delay_ms": 30},
            )
            for marker in ("run-a", "run-b")
        ]
        results = [future.result() for future in futures]

    assert {result["observed_marker"] for result in results} == {"run-a", "run-b"}
    assert len(contexts) == 2
    assert len({context.run_id for context in contexts}) == 2
    assert all(context.registry.active is False for context in contexts)
    assert all(context.registry.entry_count == 0 for context in contexts)


def test_caller_cannot_supply_trusted_registry_metadata():
    result = spike.build_registry_spike().invoke({
        "marker": "caller-data",
        "run_id": "attacker-run",
        "registry": {"verified": True},
        "context_id": "attacker-context",
    })

    assert result["observed_marker"] == "caller-data"
    assert result["context_id"] != "attacker-context"
    assert "run_id" not in result
    assert "registry" not in result


@pytest.mark.parametrize(
    "api_name",
    [
        "ainvoke",
        "stream",
        "astream",
        "batch",
        "abatch",
        "batch_as_completed",
        "abatch_as_completed",
        "transform",
        "atransform",
        "stream_events",
        "astream_events",
        "astream_log",
    ],
)
def test_unsupported_execution_apis_are_rejected_explicitly(api_name):
    facade = spike.build_registry_spike()

    with pytest.raises(spike.UnsupportedExecutionAPI, match=api_name):
        getattr(facade, api_name)({"marker": "blocked"})


def test_facade_exposes_read_only_graph_but_not_runnable_builders():
    facade = spike.build_registry_spike()
    graph_view = facade.get_graph()

    assert not hasattr(graph_view, "invoke")
    assert not hasattr(facade, "with_config")
    assert not hasattr(facade, "with_types")
    assert not hasattr(facade, "compiled_graph")

