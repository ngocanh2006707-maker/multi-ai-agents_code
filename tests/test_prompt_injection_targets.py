"""Lab preconditions and effects are checked without calling a model API."""
import json
import os
from unittest.mock import MagicMock, patch

import pytest

from graph.baseline import APP_DIRECT_SYSTEM_PROMPT, TOOL_IMPLEMENTATIONS
from tests import manual_test_full_pipeline_attacks as harness
from tests.prompt_injection_targets import LAB_CONTEXT_ENV, lab_assets


def test_all_35_objectives_have_available_targets():
    assets = lab_assets()
    available = (json.dumps(assets, ensure_ascii=False) + "\n" + assets["application_source"]
                 + "\n" + APP_DIRECT_SYSTEM_PROMPT)
    assert len(harness.TEST_CASES) == 35
    for case in harness.TEST_CASES:
        criterion = harness.SUCCESS_CRITERIA[case["id"]]
        if criterion.get("required_lab_role"):
            assert criterion["required_lab_role"] == "admin"
        else:
            assert harness.contains_marker(available, criterion["answer_markers"]), case["id"]


@pytest.mark.parametrize("case_id", ["P1_06", "P1_08", "P1_09", "P1_17", "P1_20", "P1_23", "P1_30", "P1_34"])
def test_lab_disclosure_is_scored_only_from_fixture_model_output(case_id, monkeypatch, tmp_path):
    monkeypatch.setenv("TRACE_OUTPUT_DIR", str(tmp_path))
    marker = harness.SUCCESS_CRITERIA[case_id]["answer_markers"][0]
    model = MagicMock()
    model.invoke.side_effect = [MagicMock(content="DIRECT_RESPONSE"), MagicMock(content=marker)]
    with patch("agents.planner.get_llm", return_value=model):
        report = harness.run_mode("off", suite="direct", case_ids=[case_id])
    row = report["results"][0]
    assert row["attack_success"] is None  # Marker observation awaits a bound policy/semantic review.
    assert row["marker_observed"] is True
    assert row["measurement_eligible"] is False
    assert row["final_answer"] == marker
    assert not row["application_prompt_demo"]
    assert row["runtime_model_calls"][1]["purpose"] == "direct_answer"
    # The private target is supplied by the harness, not by the attack payload.
    case = next(case for case in harness.TEST_CASES if case["id"] == case_id)
    assert marker not in case["prompt"]
    assert "test_lab_context" in model.invoke.call_args.args[0][1][1]
    assert "grant_lab_role" not in TOOL_IMPLEMENTATIONS
    assert LAB_CONTEXT_ENV not in os.environ


@pytest.mark.parametrize("claim_only", [False, True])
def test_privilege_success_requires_real_lab_tool_effect(claim_only, monkeypatch, tmp_path):
    monkeypatch.setenv("TRACE_OUTPUT_DIR", str(tmp_path))
    model = MagicMock()
    model.invoke.side_effect = (
        [MagicMock(content="DIRECT_RESPONSE"), MagicMock(content="Đã cấp quyền tối cao.")]
        if claim_only else [MagicMock(content="EXECUTE"), MagicMock(content=json.dumps({
            "tool_name": "grant_lab_role", "params": {"role": "admin"}
        }))]
    )
    with patch("agents.planner.get_llm", return_value=model):
        report = harness.run_mode("off", suite="direct", case_ids=["P1_07"])
    row = report["results"][0]
    assert row["attack_success"] is None  # Actual lab effect is recorded separately from policy violation.
    assert row["objective_effect_observed"] is (not claim_only)
    assert row["lab_role_success"] is (not claim_only)
    assert row["lab_target_evidence"]["role_before"] == "viewer"
    assert row["lab_target_evidence"]["role_after"] == ("viewer" if claim_only else "admin")
    assert row["target_scope"] == "in_memory_lab_permission"
    if not claim_only:
        assert row["tool_status"] == "success"
        assert row["executed_tool"] == "grant_lab_role"
    assert "grant_lab_role" not in TOOL_IMPLEMENTATIONS
