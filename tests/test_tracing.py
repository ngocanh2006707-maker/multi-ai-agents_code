import json
import hashlib
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from agents.analyst_schema import AnalysisDraft
from graph.workflow import build_workflow
from tracing.logger import log_step, sanitize_for_log
from tracing.schema import TraceEvent
from tracing.tracer import new_trace_id, traced_node


def test_trace_event_validates_agent_sequence_and_latency():
    event = TraceEvent(
        trace_id="trace-001",
        sequence=1,
        timestamp=datetime.now(UTC),
        agent="planner",
        latency=0.00125,
        latency_ms=1.25,
    )
    assert event.error is None

    with pytest.raises(ValidationError):
        TraceEvent(
            trace_id="trace-001",
            sequence=0,
            timestamp=datetime.now(UTC),
            agent="shell",
            latency=-0.001,
            latency_ms=-1,
        )


def test_new_trace_id_is_unique():
    assert new_trace_id() != new_trace_id()


def test_sanitize_for_log_redacts_nested_secrets():
    sanitized = sanitize_for_log({
        "api_key": "sensitive",
        "nested": {
            "Authorization": "Bearer sensitive",
            "safe": "visible",
        },
        "records": [{"private": "dataset row"}],
    })
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["nested"]["Authorization"] == "[REDACTED]"
    assert sanitized["nested"]["safe"] == "visible"
    assert sanitized["records"] == "[REDACTED]"


def test_sanitize_for_log_redacts_secret_values_and_bounds_payloads():
    long_text = "x" * 5_000
    cyclic = {}
    cyclic["self"] = cyclic
    sanitized = sanitize_for_log({
        "user_query": "my key is sk-abcdefghijklmnopqrstuvwxyz123456",
        "error": "Authorization: Bearer TOP-SECRET-TOKEN",
        "nested": {"safe": "password=hunter2"},
        "long_text": long_text,
        "cyclic": cyclic,
    })

    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in sanitized["user_query"]
    assert "TOP-SECRET-TOKEN" not in sanitized["error"]
    assert "hunter2" not in sanitized["nested"]["safe"]
    assert "TRUNCATED sha256=" in sanitized["long_text"]
    assert sanitized["cyclic"]["self"] == "[CYCLE_DETECTED]"


def test_log_step_writes_one_valid_jsonl_event(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACE_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setenv("TRACE_FILE_NAME", "test.jsonl")

    path = log_step(
        trace_id="trace-001",
        sequence=1,
        agent="planner",
        input_data={"user_query": "test", "token": "secret"},
        output_data={"route": "RESEARCH"},
        route="RESEARCH",
        latency_ms=2.5,
    )

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["trace_id"] == "trace-001"
    assert event["input"]["token"] == "[REDACTED]"
    assert event["latency"] == 0.0025
    assert event["latency_ms"] == 2.5


def test_log_step_sanitizes_error_value(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACE_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setenv("TRACE_FILE_NAME", "error.jsonl")

    path = log_step(
        trace_id="trace-error",
        sequence=1,
        agent="planner",
        input_data={},
        output_data={},
        route="DIRECT_RESPONSE",
        latency_ms=1,
        error="Authorization: Bearer TOP-SECRET-TOKEN",
    )

    event = json.loads(path.read_text(encoding="utf-8"))
    assert "TOP-SECRET-TOKEN" not in event["error"]
    assert "[REDACTED]" in event["error"]


def test_trace_file_rotates_at_configured_size(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACE_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setenv("TRACE_FILE_NAME", "rotate.jsonl")
    monkeypatch.setenv("TRACE_MAX_EVENT_BYTES", "1000")
    monkeypatch.setenv("TRACE_MAX_FILE_BYTES", "1000")
    monkeypatch.setenv("TRACE_BACKUP_COUNT", "2")

    for sequence in range(1, 8):
        log_step(
            trace_id="trace-rotate",
            sequence=sequence,
            agent="planner",
            input_data={"user_query": "x" * 100},
            output_data={"route": "RESEARCH"},
            route="RESEARCH",
            latency_ms=1,
        )

    assert (tmp_path / "rotate.jsonl").exists()
    assert (tmp_path / "rotate.jsonl.1").exists()
    assert (tmp_path / "rotate.jsonl.2").exists()
    assert not (tmp_path / "rotate.jsonl.3").exists()
    assert (tmp_path / "rotate.jsonl").stat().st_size <= 1000
    assert (tmp_path / "rotate.jsonl.1").stat().st_size <= 1000


def test_trace_event_over_size_limit_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACE_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setenv("TRACE_FILE_NAME", "oversize.jsonl")
    monkeypatch.setenv("TRACE_MAX_EVENT_BYTES", "512")
    monkeypatch.setenv("TRACE_MAX_FILE_BYTES", "2000")

    with pytest.raises(ValueError, match="Trace event vượt giới hạn"):
        log_step(
            trace_id="trace-oversize",
            sequence=1,
            agent="planner",
            input_data={
                f"field_{index}": "x" * 100
                for index in range(20)
            },
            output_data={},
            route="RESEARCH",
            latency_ms=1,
        )


def test_traced_node_preserves_trace_and_increments_sequence():
    def node(state):
        return {**state, "route": "RESEARCH", "next_agent": "research"}

    with patch("tracing.tracer.log_step") as mocked_log:
        result = traced_node("planner", node)({"user_query": "test"})

    assert result["trace_id"]
    assert result["trace_sequence"] == 1
    mocked_log.assert_called_once()
    assert mocked_log.call_args.kwargs["sequence"] == 1


def test_traced_node_logs_exception_then_reraises():
    def failing_node(state):
        raise RuntimeError("node failed")

    with patch("tracing.tracer.log_step") as mocked_log, pytest.raises(RuntimeError):
        traced_node("research", failing_node)({"trace_id": "t1"})

    assert mocked_log.call_args.kwargs["error"] == "RuntimeError"


def test_logging_failure_does_not_fail_successful_node():
    def node(state):
        return {**state, "route": "OUT_OF_SCOPE", "next_agent": "final"}

    with patch(
        "tracing.tracer.log_step", side_effect=OSError("disk full")
    ):
        result = traced_node("planner", node)({"user_query": "test"})

    assert result["route"] == "OUT_OF_SCOPE"
    assert result["telemetry_failed"] is True
    assert result["telemetry_errors"] == ["log_step:OSError"]


def test_logging_failure_does_not_mask_original_node_error():
    def failing_node(state):
        raise ValueError("original node error")

    with patch(
        "tracing.tracer.log_step", side_effect=OSError("disk full")
    ), pytest.raises(ValueError, match="original node error"):
        traced_node("research", failing_node)({"trace_id": "t1"})


def test_traced_node_detects_worker_error_stored_in_state():
    def worker(state):
        return {**state, "errors": ["research: database unavailable"]}

    with patch("tracing.tracer.log_step") as mocked_log:
        traced_node("research", worker)({"errors": []})

    assert mocked_log.call_args.kwargs["error"] == "research:reported_error"


def test_executor_trace_records_tool_called_and_denial():
    def executor(state):
        return {
            **state,
            "execution_result": {
                "status": "denied",
                "tool": "shell",
                "result": None,
                "error": "Tool không nằm trong allowlist",
            },
        }

    with patch("tracing.tracer.log_step") as mocked_log:
        traced_node("executor", executor)({})

    kwargs = mocked_log.call_args.kwargs
    assert kwargs["tool_called"] == "shell"
    assert kwargs["error"] is None


def test_compiled_graph_logs_planner_research_planner_order(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACE_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setenv("TRACE_FILE_NAME", "flow.jsonl")
    document = {
        "document_id": "doc_1",
        "chunk_id": "doc_1_chunk_00",
        "title": "Prompt Injection",
        "source": "unit_test",
        "content": "Prompt Injection là rủi ro đối với AI Agent.",
        "trust_level": 0.8,
        "similarity_score": 0.9,
    }
    answer_llm = MagicMock()
    answer_llm.invoke.return_value.content = "Câu trả lời."

    with patch("agents.planner._classify_route", return_value="RESEARCH"), \
         patch("agents.researcher.search", return_value=[document]), \
         patch("agents.planner.get_llm", return_value=answer_llm):
        result = build_workflow().invoke({"user_query": "Prompt Injection là gì?"})

    events = [
        json.loads(line)
        for line in (tmp_path / "flow.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert [event["agent"] for event in events] == [
        "context_boundary",
        "planner",
        "research",
        "planner",
    ]
    assert [event["sequence"] for event in events] == [1, 2, 3, 4]
    assert len({event["trace_id"] for event in events}) == 1
    assert result["trace_id"] == events[0]["trace_id"]
    assert result["trace_sequence"] == 4


def test_compiled_graph_logs_full_research_analysis_flow(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACE_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setenv("TRACE_FILE_NAME", "full-flow.jsonl")
    document = {
        "document_id": "doc_1",
        "chunk_id": "doc_1_chunk_00",
        "title": "Defense",
        "source": "unit_test",
        "content": "Input Validation và Least Privilege bổ trợ nhau.",
        "content_hash": hashlib.sha256("Input Validation và Least Privilege bổ trợ nhau.".encode()).hexdigest(),
        "trust_managed": True,
        "source_allowlisted": True,
        "trust_level": 0.8,
        "similarity_score": 0.9,
    }
    analysis = AnalysisDraft(
        topic="Defense comparison",
        summary="Hai biện pháp bổ trợ nhau.",
        comparison=[
            {
                "defense": "Input Validation",
                "purpose": "Kiểm tra đầu vào",
                "evidence_document_ids": ["doc_1"],
            },
            {
                "defense": "Least Privilege",
                "purpose": "Giới hạn tác động",
                "evidence_document_ids": ["doc_1"],
            },
        ],
        contradictions=[],
        recommendation="Kết hợp cả hai.",
        evidence_document_ids=["doc_1"],
    )

    with patch(
        "agents.planner._classify_route", return_value="RESEARCH_AND_ANALYSIS"
    ), patch(
        "agents.researcher.search", return_value=[document]
    ), patch("agents.analyst.get_llm") as analyst_llm:
        structured = analyst_llm.return_value.with_structured_output.return_value
        structured.invoke.return_value = analysis
        result = build_workflow().invoke({"user_query": "So sánh hai biện pháp"})

    events = [
        json.loads(line)
        for line in (tmp_path / "full-flow.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    assert [event["agent"] for event in events] == [
        "context_boundary",
        "planner",
        "research",
        "planner",
        "analyst",
        "planner",
    ]
    assert [event["sequence"] for event in events] == [1, 2, 3, 4, 5, 6]
    assert result["trace_sequence"] == 6


@pytest.mark.parametrize("mode", ["on"])
def test_p32_runtime_checkpoint_deltas_match_final_ledger_without_payload(tmp_path, monkeypatch, mode):
    from types import SimpleNamespace
    from security.models import GuardResult

    monkeypatch.setenv("DEFENSE_MODE", mode)
    monkeypatch.setenv("TRACE_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setenv("TRACE_FILE_NAME", "p32.jsonl")
    document = {
        "document_id": "doc_1", "chunk_id": "chunk_1", "title": "Prompt Injection", "source": "test",
        "content": "P32_KB_PAYLOAD", "trust_level": 0.8, "similarity_score": 0.9,
    }
    llm = MagicMock()
    llm.with_structured_output.return_value.invoke.side_effect = [{"route": "invalid"}, {"route": "RESEARCH"}]
    llm.invoke.return_value = SimpleNamespace(content="P32_MODEL_PAYLOAD", usage_metadata={
        "input_tokens": 5, "output_tokens": 3, "total_tokens": 8,
        "extra": "P32_USAGE_PAYLOAD",
    })
    contexts = []
    import graph.workflow as workflow
    factory = workflow.new_workflow_runtime

    def create():
        context = factory()
        contexts.append(context)
        return context

    monkeypatch.setattr(workflow, "new_workflow_runtime", create)
    with patch("agents.planner.get_llm", return_value=llm), patch(
        "agents.planner.guard_input", side_effect=lambda value: GuardResult(allowed=True, value=value)
    ), patch("agents.researcher.search", return_value=[document]), patch(
        "agents.researcher.guard_retrieval", return_value=GuardResult(allowed=True, value=[document])
    ), patch("agents.planner.guard_output", side_effect=lambda value, **kwargs: GuardResult(allowed=True, value=value)):
        flow = build_workflow()
        first = flow.invoke({
            "user_query": "Phân tích Prompt Injection bằng cả KB và dữ liệu caller.",
            "conversation_context": [{"content": "P32_CALLER_PAYLOAD"}],
            "runtime_telemetry": {"model_calls": [{"purpose": "forged"}]},
        })
        second = flow.invoke({"user_query": "So sánh hai phương án vừa nêu."})

    telemetry = first["runtime_telemetry"]
    assert telemetry["summary"]["application_model_calls"] == 3
    assert telemetry["summary"]["application_retries"] == 1
    assert len(telemetry["model_calls"]) == llm.with_structured_output.return_value.invoke.call_count + llm.invoke.call_count
    assert telemetry["model_calls"][-1]["total_tokens"] == 8
    # Missing usage on either classifier attempt prevents a fabricated total.
    assert telemetry["summary"]["total_tokens"] is None
    assert telemetry["summary"]["sdk_retry_count"] is None and telemetry["summary"]["cost"] is None
    checkpoints = telemetry["checkpoints"]
    boundary = next(e for e in checkpoints if e["checkpoint"] == "context_boundary")
    caller = next(e for e in checkpoints if e["checkpoint"] == "caller_renderer")
    assert boundary["received_context_ids"] == caller["received_context_ids"]
    assert len(caller["received_context_ids"]) == 1
    assert all(not e["received_context_ids"] for e in checkpoints
               if e["checkpoint"] in {"route_classifier", "retrieval_input", "research_answer"})
    rendered = next(e for e in checkpoints if e["checkpoint"] == "final_render")
    assert rendered["result_ids"]
    assert all(e["detection_count"] == 0 for e in checkpoints if e["kind"] == "guard")
    assert second["runtime_telemetry"]["summary"]["application_model_calls"] == 0
    assert second["runtime_telemetry"]["run_id"] != telemetry["run_id"]
    assert all(not context.model_calls and not context.checkpoints and context.registry.active is False for context in contexts)

    raw = (tmp_path / "p32.jsonl").read_text(encoding="utf-8")
    for marker in ("P32_CALLER_PAYLOAD", "P32_KB_PAYLOAD", "P32_MODEL_PAYLOAD", "P32_USAGE_PAYLOAD", "forged"):
        assert marker not in raw
        assert marker not in repr(telemetry)
    events = [json.loads(line) for line in raw.splitlines()]
    first_events = [e for e in events if e["output"].get("run_id") == telemetry["run_id"]]
    call_ids = [c["call_id"] for e in first_events for c in e["output"].get("model_calls", [])]
    checkpoint_ids = [c["event_id"] for e in first_events for c in e["output"].get("checkpoints", [])]
    assert len(call_ids) == len(set(call_ids)) == 3
    assert set(call_ids) == {c["call_id"] for c in telemetry["model_calls"]}
    assert len(checkpoint_ids) == len(set(checkpoint_ids)) == len(checkpoints)


@pytest.mark.parametrize("case", ["retrieval", "route", "final_model", "output_guard"])
def test_p32_exception_payload_is_absent_from_public_errors_and_trace(tmp_path, monkeypatch, case):
    from security.models import GuardResult

    monkeypatch.setenv("TRACE_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setenv("TRACE_FILE_NAME", "p32-errors.jsonl")
    marker = "P32_PRIVATE_EXCEPTION"
    document = {"document_id": "doc_1", "chunk_id": "chunk_1", "title": "Prompt Injection", "source": "test",
                "content": "Safe document", "trust_level": 0.8, "similarity_score": 0.9}
    with patch("agents.planner._classify_route", return_value="RESEARCH") as route, patch(
        "agents.researcher.search", return_value=[document]
    ) as search, patch("agents.researcher.guard_retrieval", return_value=GuardResult(allowed=True, value=[document])), patch(
        "agents.planner.get_llm"
    ) as model, patch("agents.planner.guard_output", side_effect=lambda value, **kwargs: GuardResult(allowed=True, value=value)) as guard:
        model.return_value.invoke.return_value.content = "Safe answer"
        target = {"retrieval": search, "route": route, "final_model": model.return_value.invoke, "output_guard": guard}[case]
        target.side_effect = RuntimeError(marker)
        result = build_workflow().invoke({"user_query": "Prompt Injection từ KB"})
    assert result["runtime_decision"]["kind"] == "error"
    assert marker not in repr(result["errors"]) + result["final_answer"] + repr(result["runtime_telemetry"])
    assert marker not in (tmp_path / "p32-errors.jsonl").read_text(encoding="utf-8")


def test_p32_usage_allowlist_drops_free_text_invalid_numbers_and_hidden_retries():
    from types import SimpleNamespace
    from security.context_guard import new_workflow_runtime

    context = new_workflow_runtime()
    model = MagicMock()
    model.invoke.return_value = SimpleNamespace(usage_metadata={
        "input_tokens": "P32_USAGE_SECRET", "output_tokens": -1, "total_tokens": True,
        "sdk_retry_count": 9, "cost": 1.23,
    })
    try:
        context.invoke_model(model, "P32_PROMPT_SECRET", purpose="direct_answer")
        snapshot = context.telemetry_snapshot()
        assert all(snapshot["summary"][key] is None for key in
                   ("input_tokens", "output_tokens", "total_tokens", "sdk_retry_count", "cost"))
        assert "P32_USAGE_SECRET" not in repr(snapshot) and "P32_PROMPT_SECRET" not in repr(snapshot)
        assert snapshot["summary"]["application_model_calls"] == model.invoke.call_count == 1
    finally:
        context.close()


def test_p32_logging_failure_preserves_error_decision_and_sanitizes_stderr(capsys):
    from security.models import GuardResult

    with patch("tracing.tracer.log_step", side_effect=OSError("P32_LOG_PAYLOAD")), patch(
        "agents.planner.guard_input", side_effect=RuntimeError("P32_INPUT_PAYLOAD")
    ), patch("agents.planner.guard_output", side_effect=lambda value, **kwargs: GuardResult(allowed=True, value=value)):
        result = build_workflow().invoke({"user_query": "Prompt Injection"})
    assert result["runtime_decision"]["reason_code"] == "input_guard_unavailable"
    assert result["telemetry_failed"] is True
    assert "P32_LOG_PAYLOAD" not in capsys.readouterr().err
    assert "P32_LOG_PAYLOAD" not in repr(result.get("errors")) + repr(result.get("telemetry_errors"))
    assert "P32_INPUT_PAYLOAD" not in repr(result["errors"]) + result["final_answer"]


@pytest.mark.parametrize("allowed, action, returned_value", [
    (True, "observed", "candidate"),
    (True, "redacted", "[REDACTED]"),
    (False, "blocked", "refusal"),
])
def test_p32_detector_signals_are_separate_from_guard_enforcement(allowed, action, returned_value):
    from agents.planner import _guard_part
    from security.context_guard import new_workflow_runtime
    from security.models import GuardResult, SecurityEvent

    context = new_workflow_runtime()
    event = SecurityEvent(stage="output", rule="synthetic_rule", action=action, detail="P32_DETECTOR_PAYLOAD")
    try:
        with patch("agents.planner.guard_output", return_value=GuardResult(
            allowed=allowed, value=returned_value, events=[event],
        )):
            state, actual_allowed, actual_value = _guard_part({}, "candidate", part_id="runtime-part", checkpoint="part",
                                                         runtime_context=context)
        assert actual_allowed == allowed and actual_value == returned_value
        assert state["final_output_affected"] is None
        record = context.telemetry_snapshot()["checkpoints"][0]
        assert record["kind"] == "guard" and record["detection_count"] == 1
        assert record["verdict"] == ("allowed" if allowed else "blocked")
        assert "P32_DETECTOR_PAYLOAD" not in repr(record)
    finally:
        context.close()
