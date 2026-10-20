from security.action_gate import evaluate_action_gate, params_digest
from security.config import SecuritySettings


def _settings(mode: str) -> SecuritySettings:
    return SecuritySettings(
        defense_enabled=mode == "on",
        action_gate_enabled=True,
        action_gate_require_provenance=True,
    )


def test_tool_outside_allowlist_is_blocked_in_both_modes():
    for mode in ("off", "on"):
        decision = evaluate_action_gate(
            user_query="Run a shell command",
            tool_name="shell",
            params={"command": "whoami"},
            params_source="user",
            settings=_settings(mode),
        )

        assert decision.allowed is False
        assert decision.action == "blocked"
        assert decision.reason_code == "tool_not_allowlisted"


def test_valid_read_only_tool_is_allowed_on():
    decision = evaluate_action_gate(
        user_query="Calculate the attack success rate metric.",
        tool_name="calculate_metrics",
        params={"metric": "attack_success_rate", "records": [{}]},
        params_source="planner",
        confirmed_request={
            "tool_name": "calculate_metrics",
            "params": {"metric": "attack_success_rate", "records": [{}]},
        },
        settings=_settings("on"),
    )

    assert decision.allowed is True
    assert decision.action == "allowed"
    assert decision.destructive is False


def test_retrieved_content_cannot_supply_tool_params_on():
    decision = evaluate_action_gate(
        user_query="Calculate the attack success rate metric.",
        tool_name="calculate_metrics",
        params={"metric": "defense_success_rate", "records": [{}]},
        params_source="retrieved_content",
        settings=_settings("on"),
    )

    assert decision.allowed is False
    assert decision.action == "blocked"
    assert "params_from_retrieved_content" in decision.reason_code


def test_tool_must_match_user_query_on():
    decision = evaluate_action_gate(
        user_query="Explain least privilege for agents.",
        tool_name="calculate_metrics",
        params={"metric": "attack_success_rate", "records": [{}]},
        params_source="planner",
        settings=_settings("on"),
    )

    assert decision.allowed is False
    assert "tool_query_mismatch" in decision.reason_code


def test_write_action_requires_explicit_approval_on():
    denied = evaluate_action_gate(
        user_query="Save the test result.",
        tool_name="save_test_result",
        params={"result": {}, "path": "report.json"},
        params_source="user",
        approval=False,
        settings=_settings("on"),
    )
    allowed = evaluate_action_gate(
        user_query="Save the test result.",
        tool_name="save_test_result",
        params={"result": {}, "path": "report.json"},
        params_source="user",
        approval=True,
        confirmed_request={"tool_name": "save_test_result", "params": {"result": {}, "path": "report.json"}},
        settings=_settings("on"),
    )

    assert denied.allowed is False
    assert denied.requires_approval is True
    assert "approval_required" in denied.reason_code
    assert allowed.allowed is True


def test_modified_params_are_blocked_on():
    decision = evaluate_action_gate(
        user_query="Calculate the attack success rate metric.",
        tool_name="calculate_metrics",
        params={"metric": "defense_success_rate", "records": [{}]},
        params_source="planner",
        params_modified=True,
        settings=_settings("on"),
    )

    assert decision.allowed is False
    assert "params_modified_after_planning" in decision.reason_code


def test_params_integrity_digest_detects_changed_metric_on():
    original = {"metric": "attack_success_rate", "records": [{}]}
    decision = evaluate_action_gate(
        user_query="Calculate the attack success rate metric.",
        tool_name="calculate_metrics",
        params={"metric": "defense_success_rate", "records": [{}]},
        params_source="planner",
        expected_params_digest=params_digest(original),
        settings=_settings("on"),
    )

    assert decision.allowed is False
    assert "params_integrity_mismatch" in decision.reason_code


def test_write_tool_cannot_claim_it_is_non_destructive():
    decision = evaluate_action_gate(
        user_query="Save the test result.",
        tool_name="save_test_result",
        params={"result": {}, "path": "report.json"},
        params_source="user",
        approval=False,
        destructive=False,
        settings=_settings("on"),
    )

    assert decision.allowed is False
    assert decision.destructive is True
    assert "approval_required" in decision.reason_code


def test_off_observes_context_failure_but_does_not_bypass_allowlist():
    decision = evaluate_action_gate(
        user_query="Explain least privilege.",
        tool_name="calculate_metrics",
        params={"metric": "attack_success_rate", "records": [{}]},
        params_source="retrieved_content",
        settings=_settings("off"),
    )

    assert decision.allowed is True
    assert decision.action == "observed"


def test_planner_self_digest_does_not_confirm_caller_task():
    original = {"metric": "attack_success_rate", "records": [{"attack_success": True}, {"attack_success": False}]}
    replaced = {"metric": "attack_success_rate", "records": [{"attack_success": False}, {"attack_success": False}]}
    for mode in ("on", "off"):
        for confirmed, reason in (
            (None, "missing_confirmed_execution_input"),
            ({"tool_name": "calculate_metrics", "params": original}, "caller_task_params_mismatch"),
            ({"tool_name": "run_security_test", "params": replaced}, "caller_task_tool_mismatch"),
        ):
            decision = evaluate_action_gate(
                user_query="Calculate attack success rate", tool_name="calculate_metrics",
                params=replaced, params_source="planner", expected_params_digest=params_digest(replaced),
                confirmed_request=confirmed, settings=_settings(mode),
            )
            assert reason in decision.reason_code
            assert decision.allowed is (mode == "off")
            assert decision.action == ("observed" if mode == "off" else "blocked")
