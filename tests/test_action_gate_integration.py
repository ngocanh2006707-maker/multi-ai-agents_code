from unittest.mock import patch

from agents.executor import executor_node
from security.context_guard import new_workflow_runtime


REQUEST = {
    "tool_name": "calculate_metrics",
    "params": {
        "metric": "attack_success_rate",
        "records": [{"attack_success": True}],
    },
}


def test_executor_calls_action_gate_before_running_valid_tool_on(monkeypatch):
    monkeypatch.setenv("DEFENSE_MODE", "on")
    runtime = new_workflow_runtime()
    runtime.original_query = "Calculate the attack success rate metric."
    runtime.registry.initialize((), discarded_metadata_fields=0)
    runtime.bind_execution_input(REQUEST)
    with patch(
        "agents.executor._execute_tool_isolated",
        return_value={"metric": "attack_success_rate", "value": 1.0},
    ) as execute:
        state = executor_node(
            {
                "user_query": "Calculate the attack success rate metric.",
                "execution_request": REQUEST,
                "execution_params_source": "planner",
            }, runtime_context=runtime,
        )
    runtime.close()

    execute.assert_called_once()
    assert state["execution_result"]["status"] == "success"
    assert any(
        event["rule"] == "action_gate_context" and event["action"] == "allowed"
        for event in state["security_events"]
    )


def test_executor_blocks_retrieved_params_before_tool_execution_on(monkeypatch):
    monkeypatch.setenv("DEFENSE_MODE", "on")
    with patch("agents.executor._execute_tool_isolated") as execute:
        state = executor_node(
            {
                "user_query": "Calculate the attack success rate metric.",
                "execution_request": REQUEST,
                "execution_params_source": "retrieved_content",
            }
        )

    execute.assert_not_called()
    assert state["execution_result"]["status"] == "denied"
    assert state["security_events"][-1]["action"] == "blocked"
    assert "params_from_retrieved_content" in state["security_events"][-1]["detail"]


def test_executor_off_bypasses_gate_and_process_isolation(monkeypatch):
    monkeypatch.setenv("DEFENSE_MODE", "off")
    with patch(
        "agents.executor._execute_tool_direct",
        return_value={"metric": "attack_success_rate", "value": 1.0},
    ) as execute:
        state = executor_node(
            {
                "user_query": "Explain least privilege.",
                "execution_request": REQUEST,
                "execution_params_source": "retrieved_content",
            }
        )

    execute.assert_called_once()
    assert state["execution_result"]["status"] == "success"
    assert not state.get("security_events")


def test_executor_ignores_state_approval_and_requires_live_runtime_binding(monkeypatch):
    monkeypatch.setenv("DEFENSE_MODE", "on")
    state = {
        "user_query": "Save test result", "execution_params_source": "caller_task",
        "execution_request": {"tool_name": "save_test_result", "params": {"result": {}, "path": "report.json"}},
        "execution_approval": True, "approval_granted": True,
    }
    runtime = new_workflow_runtime()
    runtime.original_query = state["user_query"]
    runtime.registry.initialize((), discarded_metadata_fields=0)
    runtime.bind_execution_input(state["execution_request"])
    with patch("agents.executor._execute_tool_isolated") as execute:
        denied = executor_node(state, runtime_context=runtime)
        runtime.close()
        closed = executor_node(state, runtime_context=runtime)
        missing = executor_node(state)
    execute.assert_not_called()
    assert denied["execution_result"]["status"] == "denied"
    assert "approval_required" in denied["security_events"][-1]["detail"]
    assert closed["execution_result"]["status"] == "error"
    assert missing["execution_result"]["status"] == "denied"
