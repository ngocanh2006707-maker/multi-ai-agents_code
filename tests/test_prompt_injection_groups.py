"""Check P1 group selection and separate reports without calling model APIs."""

import json
from unittest.mock import patch

import pytest

from tests import manual_test_full_pipeline_attacks as harness


@pytest.mark.parametrize("mode", ["off", "on"])
def test_groups_partition_original_payloads_and_keep_guards(mode):
    seen = []
    reports = []

    def record(case, selected_mode, **kwargs):
        assert selected_mode == mode
        seen.append(case)
        return {"id": case["id"], "verdict": "BYPASS_NO_SUCCESS"}

    guard_rows = [{"id": "guard_fixture", "verdict": "PASS"}]
    with patch.object(harness, "run_case", side_effect=record), patch.object(
        harness, "run_guard_checks", return_value=guard_rows
    ) as guards:
        for group in ("15", "20"):
            reports.append(harness.run_mode(mode, group=group))
    assert seen == list(harness.TEST_CASES)
    assert len({case["id"] for case in seen}) == 35
    assert [len(report["results"]) for report in reports] == [15, 20]
    assert reports[0]["selected_case_ids"] == [f"P1_{i:02d}" for i in range(1, 16)]
    assert reports[1]["selected_case_ids"] == [f"P1_{i:02d}" for i in range(16, 36)]
    assert all(report["guard_checks"] == guard_rows for report in reports)
    assert guards.call_count == 2
    assert reports[0]["experiment_fingerprint"] != reports[1]["experiment_fingerprint"]


@pytest.mark.parametrize("kwargs", [
    {"group": "15", "case_ids": ["P1_16"]},
    {"group": "20", "case_ids": ["P1_15"]},
    {"group": "15", "suite": "guards"},
    {"group": "20", "suite": "disclosure-demo"},
    {"group": "invalid"},
])
def test_invalid_group_selection_rejected_before_workflow(kwargs):
    with patch.object(harness, "run_case", side_effect=AssertionError("No model calls")):
        with pytest.raises(ValueError):
            harness.run_mode("off", **kwargs)


def test_group_can_select_one_existing_case():
    with patch.object(harness, "run_case", return_value={"id": "P1_34"}) as run:
        report = harness.run_mode("off", suite="direct", group="20", case_ids=["P1_34"])
    assert run.call_args.args[0] == harness.TEST_CASES[33]
    assert report["selected_case_ids"] == ["P1_34"]
    assert report["guard_checks"] == []


def test_cli_saves_both_modes_and_groups_to_separate_files(monkeypatch, tmp_path):
    with patch.object(harness, "run_case", side_effect=lambda case, *args, **kwargs: {
        "id": case["id"], "verdict": "BYPASS_NO_SUCCESS",
    }), patch.object(harness, "print_report"), patch.object(harness, "print_comparison") as compare:
        for group in ("15", "20"):
            monkeypatch.setattr("sys.argv", [
                "test", "--mode", "both", "--suite", "direct", "--group", group,
                "--output-dir", str(tmp_path),
            ])
            assert harness.main() == 0
        assert compare.call_count == 2
        assert all(call.args[0]["test_group"] == call.args[1]["test_group"]
                   for call in compare.call_args_list)
    paths = list(tmp_path.rglob("*.json"))
    assert len(paths) == 4
    reports = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    assert {(r["defense_mode"], r["test_group"]) for r in reports} == {
        (mode, group) for mode in ("off", "on") for group in ("15", "20")
    }
    assert harness.report_filename("off", "all").endswith("_all_off.json")
