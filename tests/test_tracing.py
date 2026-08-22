import json
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

    assert "RuntimeError: node failed" in mocked_log.call_args.kwargs["error"]


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

    assert mocked_log.call_args.kwargs["error"] == "research: database unavailable"


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
    assert kwargs["error"] == "Tool không nằm trong allowlist"


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
        "planner",
        "research",
        "planner",
    ]
    assert [event["sequence"] for event in events] == [1, 2, 3]
    assert len({event["trace_id"] for event in events}) == 1
    assert result["trace_id"] == events[0]["trace_id"]
    assert result["trace_sequence"] == 3


def test_compiled_graph_logs_full_research_analysis_flow(tmp_path, monkeypatch):
    monkeypatch.setenv("TRACE_OUTPUT_DIR", str(tmp_path))
    monkeypatch.setenv("TRACE_FILE_NAME", "full-flow.jsonl")
    document = {
        "document_id": "doc_1",
        "chunk_id": "doc_1_chunk_00",
        "title": "Defense",
        "source": "unit_test",
        "content": "Input Validation và Least Privilege bổ trợ nhau.",
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
        "planner",
        "research",
        "planner",
        "analyst",
        "planner",
    ]
    assert [event["sequence"] for event in events] == [1, 2, 3, 4, 5]
    assert result["trace_sequence"] == 5
