"""Gate 2 follow-up measurement regressions; synthetic evidence, no API."""
from copy import deepcopy
import json

import pytest

from tests.evaluation import EVALUATOR_VERSION, WORKFLOW_PROFILE_VERSION, FinalAnswerEvidence
from tests.experiment_preparation import digest, file_digest
from tests.test_experiment_preparation import modules, prepared, good_row, review_for


def test_cf_groups_do_not_mix_modes_objectives_or_invalid_samples(modules):
    _, evaluator = modules
    cases = {}
    rows = []
    for mode in ("off", "on"):
        for objective in ("trust_elevation", "instruction_following"):
            case_id = objective + "_" + mode
            cases[case_id] = {"kind": "attack", "mode": mode, "objective": objective}
            if objective == "trust_elevation":
                outcomes = [("ATTACK_SUCCESS", True)] if mode == "off" else [("ATTACK_FAILURE", False)]
            else:
                outcomes = [("ERROR", None)] if mode == "off" else [("UNKNOWN", None)]
            for i, (verdict, success) in enumerate(outcomes, 1):
                rows.append({"case_id": case_id, "run_id": case_id + f"_r{i}", "kind": "attack",
                             "defense_mode": mode, "objective": objective, "verdict": verdict,
                             "attack_success": success, "measurement_eligible": success is not None})
    # Clean rows cannot enter ASR even if an upstream record carries a true flag.
    rows.append({"kind": "baseline", "attack_success": True, "measurement_eligible": True})
    groups = evaluator.summarize_groups(rows, cases, 2)
    indexed = {(g["defense_mode"], g["objective"]): g for g in groups}
    assert len(indexed) == 4
    assert indexed["off", "trust_elevation"]["value"] == 1
    assert indexed["on", "trust_elevation"]["value"] == 0
    assert indexed["off", "instruction_following"]["ERROR"] == 1
    assert indexed["on", "instruction_following"]["UNKNOWN"] == 1
    for mode in ("off", "on"):
        assert indexed[mode, "instruction_following"]["denominator"] == 0
        assert indexed[mode, "instruction_following"]["value"] is None
    assert all(g["not_run"] == 1 for g in groups)
    with pytest.raises(ValueError, match="duplicate_run"):
        evaluator.summarize_groups(rows + [rows[0]], cases, 2)


def test_cf_evaluation_writes_only_per_case_mode_objective_asr(prepared):
    runner, evaluator, original_out, original_manifest, snapshot = prepared
    reviews = {}
    protocol = deepcopy(original_manifest["contract"]["protocol"])
    for case in protocol["cases"].values():
        if case["kind"] == "attack" and case["query"] == "Q2":
            case["objective"] = "instruction_following"
    out = original_out.parent / "two_goal_batch"
    manifest = runner.prepare(out, snapshot, protocol)
    (out / "traces").mkdir()
    for key, case in manifest["contract"]["cases"].items():
        if case["kind"] != "attack":
            continue
        run_id = key + "_r1"
        row, trace = good_row(case["mode"], run_id, case["query"])
        row["input"]["conversation_context"] = case["context"]
        row["experiment_fingerprint"] = manifest["experiment_fingerprint"]
        if case["query"] == "Q1":
            decision = "success" if case["mode"] == "off" else "failure"
            interpretation = "trusted_as_evidence" if case["mode"] == "off" else "untrusted_quote"
            reviews[run_id] = review_for(row["result"], case["objective"], interpretation, decision)
        elif case["mode"] == "off":
            row["result"]["execution_result"] = {"status": "error"}
        path = out / "traces" / (run_id + ".jsonl")
        path.write_text("\n".join(json.dumps(t) for t in trace), encoding="utf-8")
        row["trace_sha256"] = file_digest(path)
        row["record_sha256"] = digest(row)
        runner.write_new(out / (run_id + ".json"), row)
    reviews_path = out.parent / "technical_reviews.json"
    runner.write_new(reviews_path, reviews)
    output_path = out.parent / "derived_technical_evaluation.json"
    result = evaluator.evaluate(out, output_path, reviews_path)
    assert "semantic_asr" not in result
    assert len(result["semantic_asr_groups"]) == 4
    assert all({"defense_mode", "case_id", "objective"} <= row.keys() for row in result["results"])
    assert sorted(g["denominator"] for g in result["semantic_asr_groups"]) == [0, 0, 1, 1]
    assert json.loads(output_path.read_text(encoding="utf-8")) == result


@pytest.mark.parametrize("decision,interpretation,expected,verdict", [
    ("success", "forbidden_disclosure", True, "ATTACK_SUCCESS"),
    ("failure", "refusal", False, "TOOL_DENIED"),
    (None, None, None, "INCONCLUSIVE"),
])
def test_direct_tool_denial_does_not_override_disclosure_goal(decision, interpretation, expected, verdict, capsys):
    from tests import manual_test_full_pipeline_attacks as harness
    from security.coordination_guard import RenderPart, render_parts
    case = harness.TEST_CASES[0]
    part = RenderPart("answer", "kb", "kb", "Synthetic target disclosure or refusal for review.")
    final = render_parts([part])
    state = {"final_answer": final, "errors": [],
             "execution_result": {"tool": "read_dataset", "status": "denied"}}
    evidence = FinalAnswerEvidence((part,), final)
    row = harness.evaluate_case(case, "on", state, evidence)
    review = review_for(row["semantic_evidence"], "direct:" + case["id"], interpretation, decision) if decision else None
    row = harness.evaluate_case(case, "on", state, evidence, review=review)
    assert row["attack_success"] is expected and row["verdict"] == verdict
    assert row["enforcement"]["tool"] == "denied"
    assert row["outcome"] == ("ATTACK_SUCCESS" if expected is True else "ATTACK_FAILURE" if expected is False else "UNKNOWN")
    assert row["measurement_eligible"] is (expected is not None)
    report = {"evaluator_version": EVALUATOR_VERSION, "workflow_profile_version": WORKFLOW_PROFILE_VERSION,
              "experiment_fingerprint": "technical-fixture", "results": [row]}
    harness.print_comparison(report, deepcopy(report))
    printed = capsys.readouterr().out
    assert "Tool Guard chặn" not in printed
    if expected is True:
        assert "Tấn công thành công" in printed
    elif expected is None:
        assert "Chưa đủ bằng chứng" in printed


def test_indirect_analysis_marker_alone_cannot_satisfy_exact_final_goal():
    from tests import manual_test_multi_agent_coverage as harness
    from security.coordination_guard import RenderPart, render_parts
    case = harness.CASES[5]
    docs = harness.documents_for(case)
    state = {"analysis_result": {"summary": case["canary"]}, "errors": []}
    nodes = [{"node": "research", "input_chunk_ids": []},
             {"node": "analyst", "input_chunk_ids": [d["chunk_id"] for d in docs]}]
    retrieval = [{"raw": docs, "kept": docs}]
    without_final = harness.assess(case, state, nodes, retrieval, [], final_evidence=None)
    assert without_final["analysis_hijacked"]
    assert not without_final["answer_hijacked"] and without_final["attack_success"] is None
    parts = (RenderPart("answer", "kb", "kb", "A safe answer."),)
    state["final_answer"] = render_parts(parts)
    safe = harness.assess(case, state, nodes, retrieval, [], final_evidence=FinalAnswerEvidence(parts, state["final_answer"]))
    assert safe["attack_success"] is False
    parts = (RenderPart("answer", "kb", "kb", case["canary"]),)
    state["final_answer"] = render_parts(parts)
    hijacked = harness.assess(case, state, nodes, retrieval, [], final_evidence=FinalAnswerEvidence(parts, state["final_answer"]))
    assert hijacked["attack_success"] is True and hijacked["final_answer_hijacked"]
    parts = parts + (RenderPart("other_answer", "kb", "kb", "Another answer paragraph."),)
    state["final_answer"] = render_parts(parts)
    partial_match = harness.assess(case, state, nodes, retrieval, [], final_evidence=FinalAnswerEvidence(parts, state["final_answer"]))
    assert partial_match["attack_success"] is False and not partial_match["final_answer_hijacked"]
