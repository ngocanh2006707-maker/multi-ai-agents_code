"""Validate coverage attribution and fixture failures without calling model APIs."""

from argparse import Namespace
from unittest.mock import MagicMock, patch

import pytest

from security.models import GuardResult
from tests import prompt_injection_guard_coverage as coverage


@pytest.fixture
def harness():
    with patch("dotenv.load_dotenv", return_value=False):
        from tests import manual_test_full_pipeline_attacks
    return manual_test_full_pipeline_attacks


@pytest.mark.parametrize("mode", ["off", "on"])
def test_guard_suite_checks_every_layer_and_preserves_metric_task(mode, monkeypatch, tmp_path):
    monkeypatch.setenv("DEFENSE_MODE", mode)
    monkeypatch.setenv("TRACE_OUTPUT_DIR", str(tmp_path))
    with patch("agents.planner.get_llm", side_effect=AssertionError("No model API allowed")), patch(
        "agents.analyst.get_llm", side_effect=AssertionError("No model API allowed")
    ):
        rows = coverage.run_guard_checks(mode)
    assert rows and all(row["verdict"] == "PASS" for row in rows), [
        (row["id"], row.get("checks"), row.get("error_type")) for row in rows if row["verdict"] != "PASS"
    ]
    assert len({row["id"] for row in rows}) == len(rows)
    assert set(coverage.GUARD_LAYERS) <= {row["layer"] for row in rows}
    assert all(row["attack_success"] is None and not row["measurement_eligible"] for row in rows)
    chain = next(row for row in rows if row["id"] == "G_graph_clean_chain")
    if mode == "on":
        assert all(layer["call_count"] > 0 for layer in chain["guard_coverage"].values())
        assert chain["checks"]["correct_metric"]
    else:
        assert all(layer["status"] == "BYPASSED_OFF" for layer in chain["guard_coverage"].values())


def test_guard_contract_reports_regression_instead_of_assuming_blocked(monkeypatch):
    monkeypatch.setenv("DEFENSE_MODE", "on")
    monkeypatch.setattr(coverage, "COMPONENT_CASES", [("retrieval_guard", "content")])
    monkeypatch.setattr(coverage, "GRAPH_CASES", ())
    monkeypatch.setattr(coverage, "guard_retrieval", lambda documents: GuardResult(allowed=True, value=documents))
    row = coverage.run_guard_checks("on")[0]
    assert row["verdict"] == "FAIL"
    assert not row["checks"]["retained_count"]
    assert row["attack_success"] is None


def test_input_block_marks_downstream_guards_not_reached(harness, monkeypatch, tmp_path):
    monkeypatch.setenv("DEFENSE_MODE", "on")
    monkeypatch.setenv("TRACE_OUTPUT_DIR", str(tmp_path))
    with patch("agents.planner.get_llm", side_effect=AssertionError("No model API allowed")):
        row = harness.run_case(harness.TEST_CASES[0], "on")
    assert row["verdict"] == "BLOCKED_INPUT"
    assert row["guard_coverage"]["context_boundary"]["call_count"] == 1
    assert row["guard_coverage"]["input_guard"]["status"] == "BLOCKED"
    for layer in ("retrieval_guard", "coordination_guard", "confidence_gate", "action_gate"):
        assert row["guard_coverage"][layer]["status"] == "NOT_REACHED"


def test_observation_preserves_unprotected_off_workflow(harness, monkeypatch, tmp_path):
    monkeypatch.setenv("DEFENSE_MODE", "off")
    monkeypatch.setenv("TRACE_OUTPUT_DIR", str(tmp_path))
    model = MagicMock()
    model.invoke.return_value.content = "Safe fixture model answer."
    with patch("agents.planner._classify_route", return_value="DIRECT_RESPONSE"), patch(
        "agents.planner.get_llm", return_value=model
    ):
        row = harness.run_case(harness.TEST_CASES[0], "off")
    assert not row["errors"]
    assert row["attack_success"] is None
    assert row["measurement_eligible"] is False
    assert all(layer["status"] == "BYPASSED_OFF" and layer["call_count"] == 0
               for layer in row["guard_coverage"].values())


def test_evidence_alone_does_not_claim_guard_was_called():
    state = {"security_events": [{"stage": "retrieval", "action": "filtered"}]}
    result = coverage.layer_coverage("on", state, {})
    assert result["retrieval_guard"]["status"] == "NOT_REACHED"


def test_simulation_is_not_guard_coverage(harness, monkeypatch):
    monkeypatch.setenv("DEFENSE_MODE", "off")
    row = harness.run_case(harness.TEST_CASES[0], "off", simulate_off_impact=True)
    assert row["attack_success"] is None
    assert all(layer["status"] == "NOT_MEASURED" for layer in row["guard_coverage"].values())


def test_guard_only_mode_skips_direct_model_cases_and_restores_mode(harness, monkeypatch):
    monkeypatch.setenv("DEFENSE_MODE", "on")
    monkeypatch.setattr(harness, "run_guard_checks", lambda mode: [])
    with patch.object(harness, "run_case", side_effect=AssertionError("No direct model cases allowed")):
        report = harness.run_mode("off", suite="guards")
    import os
    assert os.environ["DEFENSE_MODE"] == "on"
    assert report["results"] == []
    assert report["suite"] == "guards"
    assert harness.experiment_fingerprint(suite="guards") != harness.experiment_fingerprint(suite="direct")


def test_failed_guard_check_causes_nonzero_cli_exit(harness, monkeypatch, tmp_path):
    monkeypatch.setattr(harness, "parse_args", lambda: Namespace(
        mode="on", suite="guards", output_dir=tmp_path, simulate_off_impact=False,
    ))
    monkeypatch.setattr(harness, "run_guard_checks", lambda mode: [{
        "id": "broken_guard", "verdict": "FAIL", "execution_scope": "component_call",
        "checks": {"must_block": False},
    }])
    assert harness.main() == 1
