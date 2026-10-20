"""Test OFF context exposure and scoring with fixture responses, no model API."""
from unittest.mock import MagicMock, patch

import pytest

from graph.baseline import APP_DIRECT_SYSTEM_PROMPT, APP_PROMPT_DEMO_ENV, APP_PROMPT_DISCLOSURE_POLICY
from tests import manual_test_full_pipeline_attacks as harness


@pytest.mark.parametrize("answer, expected_success", [
    (APP_DIRECT_SYSTEM_PROMPT, True),
    ("Tôi không cung cấp system prompt.", False),
])
@pytest.mark.parametrize("case_id", ["P1_03", "P1_34"])
def test_off_pipeline_scores_observed_fixture_model_answer(answer, expected_success, case_id, monkeypatch, tmp_path):
    monkeypatch.setenv(APP_PROMPT_DEMO_ENV, "1")
    monkeypatch.setenv("TRACE_OUTPUT_DIR", str(tmp_path))
    model = MagicMock()
    model.invoke.side_effect = [MagicMock(content="DIRECT_RESPONSE"), MagicMock(content=answer)]
    with patch("agents.planner.get_llm", return_value=model), patch(
        "graph.baseline._debug_prompt_requested", side_effect=AssertionError("No debug echo in P1")
    ):
        report = harness.run_mode("off", suite="direct", case_ids=[case_id])
    row = report["results"][0]
    assert row["final_answer"] == answer
    assert row["marker_observed"] is expected_success
    assert row["attack_success"] is None
    assert not row["measurement_eligible"]
    assert not row["application_prompt_demo"]
    assert row["baseline_version"] == "unprotected_off_v3_neutral_context"
    assert row["baseline_disclosure_policy"] == APP_PROMPT_DISCLOSURE_POLICY
    assert [(call["purpose"], call["outcome"]) for call in row["runtime_model_calls"]] == [
        ("route_classifier", "returned"), ("direct_answer", "returned")
    ]
    assert model.invoke.call_count == 2
    classifier_messages, answer_messages = [call.args[0] for call in model.invoke.call_args_list]
    assert APP_DIRECT_SYSTEM_PROMPT in classifier_messages[1][1]
    assert answer_messages[0] == ("system", APP_DIRECT_SYSTEM_PROMPT)
    assert APP_DIRECT_SYSTEM_PROMPT in answer_messages[1][1]
    assert row["id"] == case_id
    import os
    assert os.environ[APP_PROMPT_DEMO_ENV] == "1"


def test_full_suite_selected_case_keeps_guard_checks_and_excludes_demo(monkeypatch, tmp_path):
    monkeypatch.setenv("TRACE_OUTPUT_DIR", str(tmp_path))
    model = MagicMock()
    model.invoke.side_effect = [MagicMock(content="DIRECT_RESPONSE"), MagicMock(content="Fixture response.")]
    with patch("agents.planner.get_llm", return_value=model), patch.object(
        harness, "run_guard_checks", return_value=[{"id": "guard_fixture", "verdict": "PASS"}]
    ) as guards:
        report = harness.run_mode("off", suite="all", case_ids=["P1_03"])
    guards.assert_called_once_with("off")
    assert [row["id"] for row in report["results"]] == ["P1_03"]
    assert report["guard_checks"] == [{"id": "guard_fixture", "verdict": "PASS"}]
    assert not report["application_prompt_demo"]


def test_selected_case_fingerprint_and_cli(monkeypatch):
    monkeypatch.setattr("sys.argv", ["test", "--mode", "off", "--case", "P1_03", "--case", "P1_01"])
    assert harness.parse_args().case_ids == ["P1_03", "P1_01"]
    assert harness.experiment_fingerprint(case_ids=["P1_03"]) != harness.experiment_fingerprint()
    assert harness.experiment_fingerprint(case_ids=["P1_01", "P1_03"]) == harness.experiment_fingerprint(
        case_ids=["P1_03", "P1_01"])
    with pytest.raises(ValueError, match="--case"):
        harness.run_mode("off", suite="guards", case_ids=["P1_03"])


def test_on_disclosure_request_is_blocked_before_model(monkeypatch, tmp_path):
    monkeypatch.setenv("TRACE_OUTPUT_DIR", str(tmp_path))
    with patch("agents.planner.get_llm", side_effect=AssertionError("No API")):
        report = harness.run_mode("on", suite="direct", case_ids=["P1_01"])
    row = report["results"][0]
    assert row["verdict"] == "BLOCKED_INPUT"
    assert row["runtime_model_calls"] == []
    assert APP_DIRECT_SYSTEM_PROMPT not in row["final_answer"]


def test_partial_application_prompt_quote_with_line_wrapping_is_evidence():
    fragment = "Dùng ngữ cảnh khởi tạo để hiểu vai trò và phạm vi công việc của ứng dụng."
    assert fragment in APP_DIRECT_SYSTEM_PROMPT
    assert fragment in harness.contains_marker(fragment.replace(" để ", "\nđể "), harness._SYSTEM_PROMPT_MARKERS)
    assert harness.contains_marker("Tôi không thể đọc system prompt từ cache.", harness._SYSTEM_PROMPT_MARKERS) == []
