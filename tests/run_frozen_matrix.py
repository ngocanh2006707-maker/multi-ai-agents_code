"""Offline prepare/preview, separately authorized subprocess execution and derivation.

This module imports no workflow/provider at startup. Approval records are external
owner decisions, never a boolean from a payload. Failed attempts are not retried.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from importlib import metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from time import perf_counter
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tests.evaluation import EVALUATOR_VERSION, SEMANTIC_RUBRIC_VERSION, WORKFLOW_PROFILE_VERSION
from tests.experiment_preparation import digest, evidence_status, file_digest, frozen_contract, tree_hashes
from tests.experiment_adapter import (case_for_run, invoke_case, normalize_matrix, redact_credentials,
                                      required_controls, run_ids, score, summarize, utility_assessment,
                                      SCORER_VERSION, rubric_version)

ENV_KEYS = ("MODEL_PROVIDER", "MODEL_NAME", "EMBEDDING_PROVIDER", "EMBEDDING_MODEL",
            "EMBEDDING_LOCAL_FILES_ONLY", "VECTOR_DB_COLLECTION", "RETRIEVAL_TOP_K",
            "RETRIEVAL_MIN_SIMILARITY", "OFF_APP_PROMPT_DISCLOSURE_DEMO", "EXECUTOR_TOOL_TIMEOUT_SECONDS")


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_new(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def settings():
    return {"environment": {key: os.environ.get(key) for key in ENV_KEYS},
            "python": sys.version,
            "packages": sorted([d.metadata["Name"], d.version] for d in metadata.distributions())}


def owner_record(record, kind):
    if (not isinstance(record, dict) or record.get("kind") != kind
            or record.get("approved") is not True or not record.get("owner_identity")
            or not record.get("decision_evidence")):
        raise ValueError("owner_decision_missing:" + kind)


def in_artifacts(path, root=ROOT):
    path, base = Path(path).resolve(), (Path(root) / "artifacts").resolve()
    if not path.is_relative_to(base) or path == base:
        raise ValueError("batch_must_be_new_directory_under_artifacts")
    return path


def prepare(output, *, protocol, tier, snapshot, snapshot_decision, policy, data_manifest, root=ROOT):
    """Requires source snapshot permission; does not authorize any invocation."""
    output = in_artifacts(output, root)
    snapshot = Path(snapshot).resolve()
    owner_record(snapshot_decision, "owner_snapshot_preparation")
    hashes = tree_hashes(snapshot)
    if not hashes or snapshot_decision.get("snapshot_hashes") != hashes:
        raise ValueError("source_snapshot_not_approved")
    if snapshot_decision.get("source_path") != str(snapshot):
        raise ValueError("snapshot_source_binding_invalid")
    cases = normalize_matrix(protocol, tier)
    if not policy or not data_manifest:
        raise ValueError("policy_and_data_manifest_required")
    if os.environ.get("OFF_APP_PROMPT_DISCLOSURE_DEMO", "").lower() in {"true", "1", "yes", "on"}:
        raise ValueError("disclosure_demo_outside_profile")
    if os.environ.get("P1_TEST_LAB_CONTEXT"):
        raise ValueError("external_lab_context_not_allowed")
    for case in cases.values():
        if case.get("policy_id") and case["policy_id"] not in policy:
            raise ValueError("policy_definition_missing")
        if case.get("policy_id"):
            definition = policy[case["policy_id"]]
            if (not isinstance(definition, dict) or case["objective"] not in definition.get("objectives", [])
                    or not all(isinstance(definition.get(k), str) and definition[k].strip()
                               for k in ("allowed_use", "forbidden_goal", "success_evidence"))):
                raise ValueError("policy_definition_incomplete")
    if (data_manifest.get("input_sha256") != {rid: case_for_run(cases, rid)["public_input_sha256"] for rid in run_ids(cases)}
            or data_manifest.get("snapshot_hashes") != hashes
            or data_manifest.get("fixture_sha256") != digest({key: case.get("fixture_documents") for key, case in cases.items()})
            or not data_manifest.get("destination") or not data_manifest.get("data_description")):
        raise ValueError("data_manifest_binding_invalid")
    output.mkdir(parents=True, exist_ok=False)
    shutil.copytree(snapshot, output / "pinned_snapshot")
    if tree_hashes(output / "pinned_snapshot") != hashes:
        raise ValueError("snapshot_copy_mismatch")
    contract = frozen_contract(root, output / "pinned_snapshot", cases, settings(), repetitions=1)
    manifest = {"schema_version": 1, "adapter_version": "frozen_adapter_v1", "scorer_version": SCORER_VERSION, "tier": tier,
                "root": str(Path(root).resolve()), "protocol": protocol, "policy": policy,
                "data_manifest": data_manifest, "snapshot_preparation_decision": snapshot_decision,
                "contract": contract, "evaluator_version": EVALUATOR_VERSION,
                "rubric_version": SEMANTIC_RUBRIC_VERSION, "profile": WORKFLOW_PROFILE_VERSION,
                "case_rubric_versions": {key: rubric_version(case) for key, case in cases.items()},
                "execution_authorized": False}
    manifest["experiment_fingerprint"] = digest(manifest)
    write_new(output / "manifest.json", manifest)
    return manifest


def require_frozen(batch):
    batch = Path(batch).resolve()
    manifest = read(batch / "manifest.json")
    fingerprint = manifest["experiment_fingerprint"]
    if digest({k: v for k, v in manifest.items() if k != "experiment_fingerprint"}) != fingerprint:
        raise ValueError("manifest_fingerprint_invalid")
    cases = normalize_matrix(manifest["protocol"], manifest["tier"])
    current = frozen_contract(manifest["root"], batch / "pinned_snapshot", cases, settings(), repetitions=1)
    if current != manifest["contract"]:
        raise ValueError("frozen_dependency_or_snapshot_drift")
    return manifest


def preview(batch):
    manifest = require_frozen(batch)
    cases = manifest["contract"]["cases"]
    return {"experiment_fingerprint": manifest["experiment_fingerprint"], "invocations": 0,
            "runs": [{"run_id": rid, "kind": case_for_run(cases, rid)["kind"],
                      "input_sha256": case_for_run(cases, rid)["public_input_sha256"],
                      "controls": required_controls(cases, case_for_run(cases, rid))
                      if case_for_run(cases, rid)["kind"] != "baseline" else []}
                     for rid in run_ids(cases)],
            "prerequisites": ["owner_policy", "owner_matrix", "owner_snapshot", "owner_api_approval",
                              "actual_batch_fingerprint", "paired_control_utility_reviews", "budget"]}


def authorization(manifest, approvals, run_id):
    case_for_run(manifest["contract"]["cases"], run_id)
    bindings = {"owner_policy": digest(manifest["policy"]),
                "owner_matrix": digest(manifest["protocol"]),
                "owner_snapshot": digest(manifest["contract"]["snapshot_hashes"])}
    for kind, bound in bindings.items():
        record = approvals.get(kind)
        owner_record(record, kind)
        if record.get("experiment_fingerprint") != manifest["experiment_fingerprint"] or record.get("subject_sha256") != bound:
            raise ValueError("owner_subject_binding_invalid:" + kind)
    api = approvals.get("owner_api_approval")
    owner_record(api, "owner_api_approval")
    if (api.get("experiment_fingerprint") != manifest["experiment_fingerprint"]
            or api.get("data_manifest_sha256") != digest(manifest["data_manifest"])
            or api.get("destination") != manifest["data_manifest"].get("destination")
            or not api.get("destination") or run_id not in api.get("run_ids", [])
            or len(set(api["run_ids"])) != len(api["run_ids"])
            or not set(api["run_ids"]).issubset(run_ids(manifest["contract"]["cases"]))
            or api.get("sdk_retries_and_cost_unmeasured_acknowledged") is not True):
        raise ValueError("api_scope_binding_invalid")
    provider = manifest["contract"]["settings"]["environment"].get("MODEL_PROVIDER") or "google"
    expected_destination = {"google": "Google Gemini API", "gemini": "Google Gemini API",
                            "openai": "OpenAI API", "anthropic": "Anthropic API"}.get(provider.lower())
    if api["destination"] != expected_destination:
        raise ValueError("provider_destination_mismatch")
    environment = manifest["contract"]["settings"]["environment"]
    if manifest["tier"] != "indirect_fixture" and (
            environment.get("EMBEDDING_PROVIDER") != "local"
            or str(environment.get("EMBEDDING_LOCAL_FILES_ONLY", "")).lower() not in {"true", "1", "yes"}):
        raise ValueError("snapshot_tiers_require_local_offline_embedding")
    for name in ("max_workflow_invocations", "max_application_model_calls", "per_run_model_calls", "timeout_seconds"):
        if type(api.get(name)) is not int or api[name] < 1:
            raise ValueError("api_budget_invalid:" + name)
    if api["timeout_seconds"] > manifest["protocol"].get("timeout_seconds", 300):
        raise ValueError("timeout_outside_protocol")
    return api


def load_row(batch, run_id, manifest):
    case = case_for_run(manifest["contract"]["cases"], run_id)
    row = read(Path(batch) / "records" / (run_id + ".json"))
    expected = {"run_id": run_id, "case_id": case["case_id"], "defense_mode": case["mode"],
                "input": case["public_input"], "experiment_fingerprint": manifest["experiment_fingerprint"],
                "input_sha256": case["public_input_sha256"]}
    if (any(row.get(k) != v for k, v in expected.items())
            or row.get("record_sha256") != digest({k: v for k, v in row.items() if k != "record_sha256"})):
        raise ValueError("cached_record_binding_invalid")
    request = read(Path(batch) / "requests" / (run_id + ".json"))
    attempt = read(Path(batch) / "attempts" / (run_id + ".json"))
    if (row.get("request_sha256") != digest(request)
            or row.get("reservation_sha256") != attempt.get("reservation_sha256")
            or attempt.get("reservation_sha256") != digest({k: v for k, v in attempt.items() if k != "reservation_sha256"})
            or attempt.get("approvals_sha256") != digest(request["approvals"])
            or attempt.get("utility_reviews_sha256") != digest(request["reviews"])):
        raise ValueError("cached_authorization_binding_invalid")
    authorization(manifest, request["approvals"], run_id)
    path = Path(batch) / "traces" / (run_id + ".jsonl")
    if not path.is_file() or row.get("trace_sha256") != file_digest(path):
        raise ValueError("trace_missing_or_changed")
    trace = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return row, trace


def gate(batch, manifest, case, reviews):
    if case["kind"] == "baseline":
        return
    cases = manifest["contract"]["cases"]
    for run_id in required_controls(cases, case):
        try:
            row, trace = load_row(batch, run_id, manifest)
        except (FileNotFoundError, ValueError) as exc:
            raise ValueError("paired_control_evidence_missing:" + run_id) from exc
        control = case_for_run(cases, run_id)
        assessment = utility_assessment(row, trace, control, manifest["experiment_fingerprint"], reviews.get(run_id))
        if not assessment["passed"]:
            raise ValueError("paired_control_utility_invalid:" + run_id + ":" + ",".join(assessment["reasons"]))


def require_healthy_history(batch, manifest):
    for path in sorted((Path(batch) / "records").glob("*.json")):
        row, trace = load_row(batch, path.stem, manifest)
        if evidence_status(row, trace) != "OBSERVABLE":
            raise ValueError("previous_run_not_observable_new_batch_required")
    attempts = {p.stem for p in (Path(batch) / "attempts").glob("*.json")}
    recorded = {p.stem for p in (Path(batch) / "records").glob("*.json")}
    if attempts - recorded:
        raise ValueError("unfinished_attempt_new_batch_required")


@contextmanager
def execution_lock(batch):
    path = Path(batch) / ".execution.lock"
    with path.open("x", encoding="utf-8") as stream:
        stream.write(str(os.getpid()))
    try:
        yield
    finally:
        path.unlink()  # Only our newly created mutex; source evidence is never deleted.


def reserve(batch, manifest, api, run_id, approvals, reviews):
    attempts = [read(p) for p in (Path(batch) / "attempts").glob("*.json")]
    if (len(attempts) >= api["max_workflow_invocations"]
            or sum(a["reserved_model_calls"] for a in attempts) + api["per_run_model_calls"] > api["max_application_model_calls"]):
        raise ValueError("batch_budget_exhausted")
    attempt = {"run_id": run_id, "experiment_fingerprint": manifest["experiment_fingerprint"],
               "reserved_model_calls": api["per_run_model_calls"],
               "approvals_sha256": digest(approvals), "utility_reviews_sha256": digest(reviews)}
    attempt["reservation_sha256"] = digest(attempt)
    write_new(Path(batch) / "attempts" / (run_id + ".json"), attempt)
    return attempt


def worker(batch, run_id, approvals, reviews):
    """Recheck authorization and controls BEFORE workflow imports or construction."""
    batch = Path(batch).resolve()
    manifest = require_frozen(batch)
    api = authorization(manifest, approvals, run_id)
    if os.environ.get("P1_TEST_LAB_CONTEXT"):
        raise ValueError("external_lab_context_not_allowed")
    case = case_for_run(manifest["contract"]["cases"], run_id)
    gate(batch, manifest, case, reviews)
    attempt = read(batch / "attempts" / (run_id + ".json"))
    if (attempt.get("reservation_sha256") != digest({k: v for k, v in attempt.items() if k != "reservation_sha256"})
            or attempt.get("run_id") != run_id or attempt.get("experiment_fingerprint") != manifest["experiment_fingerprint"]
            or attempt.get("approvals_sha256") != digest(approvals)
            or attempt.get("utility_reviews_sha256") != digest(reviews)
            or attempt.get("reserved_model_calls") != api["per_run_model_calls"]):
        raise ValueError("worker_reservation_invalid")
    attempts = [read(p) for p in (batch / "attempts").glob("*.json")]
    if (len(attempts) > api["max_workflow_invocations"]
            or sum(a["reserved_model_calls"] for a in attempts) > api["max_application_model_calls"]):
        raise ValueError("worker_budget_exhausted")
    # Exclusive claim prevents manual worker re-entry, even after failure.
    write_new(batch / "worker_claims" / (run_id + ".json"), {"reservation_sha256": attempt["reservation_sha256"]})
    work = batch / "working_snapshots" / run_id
    shutil.copytree(batch / "pinned_snapshot", work)
    trace_dir = batch / "traces"
    trace_dir.mkdir(exist_ok=True)
    trace_path = trace_dir / (run_id + ".jsonl")
    if trace_path.exists():
        raise ValueError("trace_already_exists")
    runtime_env = {"VECTOR_DB_PATH": str(work), "DEFENSE_MODE": case["mode"],
                   "TRACE_OUTPUT_DIR": str(trace_dir), "TRACE_FILE_NAME": trace_path.name,
                   "TRACE_MAX_FILE_BYTES": str(128 * 1024 * 1024), "TRACE_BACKUP_COUNT": "0"}
    def recheck():
        current = require_frozen(batch)
        authorization(current, approvals, run_id)
        gate(batch, current, case, reviews)
    with patch.dict(os.environ, runtime_env):
        result = invoke_case(case, model_call_limit=api["per_run_model_calls"], pre_call=recheck)
    result, redacted = redact_credentials(result)
    result["evidence_redacted"] = redacted
    write_new(batch / "workers" / (run_id + ".json"), result)
    require_frozen(batch)
    return result


def execute(batch, run_id, approvals, reviews, *, launch=None):
    """One run per subprocess; the test-only launch seam never changes public CLI."""
    batch = Path(batch).resolve()
    with execution_lock(batch):
        manifest = require_frozen(batch)
        api = authorization(manifest, approvals, run_id)
        case = case_for_run(manifest["contract"]["cases"], run_id)
        if (batch / "records" / (run_id + ".json")).exists():
            row, trace = load_row(batch, run_id, manifest)
            if evidence_status(row, trace) != "OBSERVABLE":
                raise ValueError("cached_run_not_observable")
            return row
        require_healthy_history(batch, manifest)
        gate(batch, manifest, case, reviews)
        reserve(batch, manifest, api, run_id, approvals, reviews)
        write_new(batch / "requests" / (run_id + ".json"), {"approvals": approvals, "reviews": reviews})
        returncode, status = None, "completed"
        started = perf_counter()
        if launch is not None:
            returncode = launch(batch, run_id, approvals, reviews)
        else:
            command = [sys.executable, "-B", "-X", "utf8", str(Path(__file__).resolve()), "worker",
                       "--batch", str(batch), "--run-id", run_id, "--request", str(batch / "requests" / (run_id + ".json"))]
            # Output is deliberately not persisted: it may contain provider credentials.
            try:
                process = subprocess.run(command, cwd=manifest["root"], capture_output=True,
                                         timeout=api["timeout_seconds"], check=False,
                                         env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
                returncode = process.returncode
            except subprocess.TimeoutExpired:
                status = "timeout"
        work_file = batch / "workers" / (run_id + ".json")
        row = read(work_file) if work_file.is_file() else {"status": "process_error", "result": {}, "capture": {}}
        if status == "timeout":
            row["status"] = status
        trace = batch / "traces" / (run_id + ".jsonl")
        row.update(run_id=run_id, case_id=case["case_id"], defense_mode=case["mode"],
                   process_seconds=perf_counter() - started,
                   experiment_fingerprint=manifest["experiment_fingerprint"], input=case["public_input"],
                   input_sha256=case["public_input_sha256"], process_returncode=returncode,
                   request_sha256=digest({"approvals": approvals, "reviews": reviews}),
                   reservation_sha256=read(batch / "attempts" / (run_id + ".json"))["reservation_sha256"],
                   trace_sha256=file_digest(trace) if trace.is_file() else None)
        try:
            require_frozen(batch)
        except ValueError:
            row.update(status="process_error", drift_detected=True)
        row["record_sha256"] = digest(row)
        write_new(batch / "records" / (run_id + ".json"), row)
        return row


def derive(batch, output, semantic_reviews):
    batch, output = Path(batch).resolve(), Path(output).resolve()
    if output == batch or output.is_relative_to(batch):
        raise ValueError("derived_output_must_be_outside_source_batch")
    manifest = require_frozen(batch)
    cases, rows = manifest["contract"]["cases"], []
    for path in sorted((batch / "records").glob("*.json")):
        row, trace = load_row(batch, path.stem, manifest)
        case = case_for_run(cases, path.stem)
        rows.append({"run_id": path.stem, "source_record_sha256": row["record_sha256"],
                     **score(row, trace, case, semantic_reviews.get(path.stem))})
    derived = {"experiment_fingerprint": manifest["experiment_fingerprint"], "rows": rows,
               "groups": summarize(rows, cases), "reviews_sha256": digest(semantic_reviews),
               "evaluator_version": EVALUATOR_VERSION, "rubric_version": SEMANTIC_RUBRIC_VERSION,
               "scorer_version": SCORER_VERSION,
               "case_rubric_versions": {key: rubric_version(case) for key, case in cases.items()},
               "scope": "per_tier_profile_case_mode_objective_policy_only"}
    write_new(output, derived)
    return derived


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "preview", "run", "worker", "derive"])
    parser.add_argument("--batch", type=Path, required=True)
    parser.add_argument("--spec", type=Path, help="prepare inputs including snapshot owner permission")
    parser.add_argument("--request", type=Path, help="external approvals and utility reviews")
    parser.add_argument("--run-id")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--semantic-reviews", type=Path)
    args = parser.parse_args()
    if args.command == "prepare":
        spec = read(args.spec)
        result = prepare(args.batch, protocol=spec["protocol"], tier=spec["tier"], snapshot=spec["snapshot"],
                         snapshot_decision=spec["snapshot_decision"], policy=spec["policy"], data_manifest=spec["data_manifest"])
        print(json.dumps({"experiment_fingerprint": result["experiment_fingerprint"], "invocations": 0}))
    elif args.command == "preview":
        print(json.dumps(preview(args.batch), ensure_ascii=False, indent=2))
    elif args.command in {"run", "worker"}:
        request = read(args.request)
        result = (execute if args.command == "run" else worker)(args.batch, args.run_id, request["approvals"], request.get("reviews", {}))
        print(json.dumps({"status": result["status"]}))
    else:
        derive(args.batch, args.output, read(args.semantic_reviews))


if __name__ == "__main__":
    main()
