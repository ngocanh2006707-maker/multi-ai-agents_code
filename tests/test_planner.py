"""
Test logic điều phối của Planner KHÔNG cần gọi LLM thật (mock
agents.planner._classify_route) — chỉ kiểm tra state machine
(route -> plan -> next_agent) hoạt động đúng qua nhiều lượt.
"""

from unittest.mock import patch, MagicMock

import pytest
from pydantic import ValidationError

from agents.planner import (
    _answer_from_analysis,
    _answer_from_research,
    _classify_route,
    planner_node,
)
from agents.planner_schema import RouteDecision


def _mock_llm_response(text: str):
    mock_response = MagicMock()
    mock_response.content = text
    mock_llm = MagicMock()
    mock_llm.invoke.return_value = mock_response
    return mock_llm


def _run_full_loop(user_query: str, mocked_route: str):
    """Giả lập vòng lặp Planner <-> Worker, với Worker là no-op
    (chỉ set current_agent, không thật sự sinh dữ liệu) — đủ để
    kiểm tra thứ tự next_agent mà Planner quyết định.

    Mock cả get_llm() vì DIRECT_RESPONSE gọi LLM để soạn câu trả lời
    trực tiếp — test này không cần API thật.
    """
    mock_llm = _mock_llm_response("(câu trả lời giả lập)")
    with patch("agents.planner._classify_route", return_value=mocked_route), \
         patch("agents.planner.get_llm", return_value=mock_llm), \
         patch(
             "agents.planner._build_execution_request",
             return_value={
                 "tool_name": "calculate_metrics",
                 "params": {"metric": "attack_success_rate", "records": []},
             },
         ):
        state = {"user_query": user_query, "current_agent": None}
        history = []

        state = planner_node(state)
        history.append(state["next_agent"])

        # Lặp cho tới khi Planner báo "final"
        while state["next_agent"] != "final":
            worker_just_ran = state["next_agent"]
            state = {**state, "current_agent": worker_just_ran}
            if worker_just_ran == "research":
                state["retrieved_documents"] = [{
                    "document_id": "mock_doc",
                    "chunk_id": "mock_doc_chunk_00",
                    "content": "Mock research evidence.",
                    "source": "unit_test",
                    "trust_level": 1.0,
                    "similarity_score": 1.0,
                }]
            elif worker_just_ran == "analyst":
                state["analysis_result"] = {
                    "topic": "mock",
                    "summary": "mock",
                    "comparison": [],
                    "contradictions": [],
                    "recommendation": "mock",
                    "confidence": 0.5,
                }
            elif worker_just_ran == "executor":
                state["execution_result"] = {
                    "status": "success",
                    "tool": "calculate_metrics",
                    "result": {},
                    "error": None,
                }
            state = planner_node(state)
            history.append(state["next_agent"])

    return state, history


def test_research_answer_uses_kb_internally_without_exposing_source_metadata():
    mock_llm = _mock_llm_response("Nội dung đã được tổng hợp.")
    state = {
        "user_query": "Prompt injection là gì?",
        "retrieved_documents": [{
            "document_id": "secret_doc_id",
            "chunk_id": "secret_chunk_id",
            "title": "Private title",
            "source": "Private source",
            "content": "Prompt injection làm thay đổi hành vi dự kiến.",
            "trust_level": 0.9,
            "similarity_score": 0.95,
        }],
    }

    with patch("agents.planner.get_llm", return_value=mock_llm):
        answer = _answer_from_research(state)

    messages = mock_llm.invoke.call_args.args[0]
    system_prompt = messages[0][1]
    kb_context = messages[1][1]
    assert answer == "Nội dung đã được tổng hợp."
    assert "Không thêm mục nguồn" in system_prompt
    assert "Private title" not in kb_context
    assert "Private source" not in kb_context
    assert "secret_doc_id" not in kb_context
    assert "secret_chunk_id" not in kb_context


def test_analysis_answer_keeps_evidence_internal():
    answer = _answer_from_analysis({
        "analysis_result": {
            "topic": "Prompt Injection",
            "summary": "Nên áp dụng phòng thủ nhiều lớp.",
            "comparison": [{
                "defense": "Input Validation",
                "purpose": "Kiểm tra đầu vào",
                "evidence_document_ids": ["doc_private_1"],
            }],
            "contradictions": [{
                "claim_a": "Biện pháp A hiệu quả.",
                "claim_b": "Biện pháp A có giới hạn.",
                "document_ids": ["doc_private_1", "doc_private_2"],
                "explanation": "Khác điều kiện thử nghiệm.",
            }],
            "recommendation": "Kết hợp nhiều lớp kiểm soát.",
            "evidence_document_ids": ["doc_private_1"],
            "confidence": 0.8,
        }
    })

    assert "doc_private_1" not in answer
    assert "doc_private_2" not in answer
    assert "Tài liệu bằng chứng" not in answer
    assert "  Nguồn:" not in answer
    assert "Nên áp dụng phòng thủ nhiều lớp." in answer


def test_direct_response_route_goes_straight_to_final():
    state, history = _run_full_loop("Xin chào", "DIRECT_RESPONSE")
    assert history == ["final"]
    assert state["plan"] == []


def test_out_of_scope_route_goes_straight_to_final():
    state, history = _run_full_loop("Công thức nấu phở?", "OUT_OF_SCOPE")
    assert history == ["final"]


def test_research_route_calls_research_then_final():
    state, history = _run_full_loop("Prompt injection là gì?", "RESEARCH")
    assert history == ["research", "final"]


def test_research_and_analysis_route_order():
    state, history = _run_full_loop(
        "So sánh Input Validation và Least Privilege", "RESEARCH_AND_ANALYSIS"
    )
    assert history == ["research", "analyst", "final"]


def test_research_analysis_execute_full_order():
    state, history = _run_full_loop(
        "Tra cứu, phân tích rồi tính metric cho X", "RESEARCH_ANALYSIS_EXECUTE"
    )
    assert history == ["research", "analyst", "executor", "final"]


def test_execute_route_builds_structured_execution_request():
    request = {
        "tool_name": "calculate_metrics",
        "params": {
            "metric": "attack_success_rate",
            "records": [{"attack_success": True}],
        },
    }
    with patch("agents.planner._classify_route", return_value="EXECUTE"), \
         patch("agents.planner._build_execution_request", return_value=request):
        state = planner_node({"user_query": "Tính Attack Success Rate"})

    assert state["next_agent"] == "executor"
    assert state["execution_request"] == request


def test_structured_classifier_returns_valid_route():
    mock_llm = MagicMock()
    structured = mock_llm.with_structured_output.return_value
    structured.invoke.return_value = RouteDecision(route="RESEARCH")
    with patch("agents.planner.get_llm", return_value=mock_llm):
        assert _classify_route("Prompt Injection là gì?") == "RESEARCH"


def test_analysis_without_context_is_upgraded_to_research_and_analysis():
    mock_llm = MagicMock()
    structured = mock_llm.with_structured_output.return_value
    structured.invoke.return_value = RouteDecision(route="ANALYSIS")
    with patch("agents.planner.get_llm", return_value=mock_llm):
        route = _classify_route("So sánh hai biện pháp", has_analysis_context=False)
    assert route == "RESEARCH_AND_ANALYSIS"


def test_classifier_retries_validation_error_once():
    with pytest.raises(ValidationError) as validation_error:
        RouteDecision.model_validate({"route": "INVALID_ROUTE"})

    mock_llm = MagicMock()
    structured = mock_llm.with_structured_output.return_value
    structured.invoke.side_effect = [
        validation_error.value,
        RouteDecision(route="RESEARCH"),
    ]
    with patch("agents.planner.get_llm", return_value=mock_llm):
        assert _classify_route("Prompt Injection là gì?") == "RESEARCH"
    assert structured.invoke.call_count == 2


def test_classifier_does_not_retry_non_transient_programming_error():
    mock_llm = MagicMock()
    structured = mock_llm.with_structured_output.return_value
    structured.invoke.side_effect = RuntimeError("bad configuration")
    with patch("agents.planner.get_llm", return_value=mock_llm), \
         pytest.raises(RuntimeError, match="Không thể phân loại route"):
        _classify_route("Prompt Injection là gì?")
    assert structured.invoke.call_count == 1


def test_conversation_context_allows_analysis_route_without_research():
    with patch("agents.planner._classify_route", return_value="ANALYSIS") as classify:
        state = planner_node({
            "user_query": "So sánh hai phương án vừa nêu",
            "conversation_context": [
                {"role": "assistant", "content": "Phương án A và B"}
            ],
        })

    assert classify.call_args.kwargs["has_analysis_context"] is True
    assert state["next_agent"] == "analyst"


def test_classification_failure_stops_fail_closed():
    with patch(
        "agents.planner._classify_route", side_effect=RuntimeError("model down")
    ):
        state = planner_node({"user_query": "Prompt Injection là gì?"})
    assert state["next_agent"] == "final"
    assert "classification_error" in state["errors"][0]


@pytest.mark.parametrize("state", [
    {},
    {"user_query": "   "},
    {"user_query": None},
])
def test_invalid_initial_state_stops_without_key_error(state):
    result = planner_node(state)
    assert result["next_agent"] == "final"
    assert result["plan"] == []
    assert "invalid_state" in result["errors"][-1]


@pytest.mark.parametrize(
    ("worker", "result_field", "result_value"),
    [
        ("research", None, None),
        ("research", "retrieved_documents", [{"anything": "goes"}]),
        ("analyst", "analysis_result", []),
        ("analyst", "analysis_result", {}),
        ("executor", "execution_result", "not-a-dict"),
        ("executor", "execution_result", {}),
    ],
)
def test_planner_rejects_invalid_worker_output_contract(
    worker, result_field, result_value
):
    state = {
        "user_query": "Kiểm tra output worker",
        "plan": [worker],
        "current_agent": worker,
        "errors": [],
    }
    if result_field is not None:
        state[result_field] = result_value

    result = planner_node(state)

    assert result["next_agent"] == "final"
    assert result["plan"] == []
    assert "worker_contract_error" in result["errors"][-1]


def test_planner_rejects_result_from_unexpected_worker():
    state = planner_node({
        "user_query": "Prompt Injection là gì?",
        "route": "RESEARCH",
        "plan": ["research"],
        "current_agent": "executor",
    })
    assert state["next_agent"] == "final"
    assert "expected 'research'" in state["errors"][0]


def test_planner_stops_after_worker_error():
    state = planner_node({
        "user_query": "Prompt Injection là gì?",
        "route": "RESEARCH",
        "plan": ["research", "analyst"],
        "current_agent": "research",
        "errors": ["research: database unavailable"],
    })
    assert state["next_agent"] == "final"
    assert state["plan"] == []


def test_planner_does_not_call_analyst_when_research_is_empty():
    state = planner_node({
        "user_query": "So sánh hai biện pháp",
        "route": "RESEARCH_AND_ANALYSIS",
        "plan": ["research", "analyst"],
        "current_agent": "research",
        "retrieved_documents": [],
    })
    assert state["next_agent"] == "final"
    assert state["plan"] == []


def test_low_confidence_analysis_stops_before_executor():
    state = planner_node({
        "user_query": "Phân tích rồi chạy thử nghiệm",
        "route": "RESEARCH_ANALYSIS_EXECUTE",
        "plan": ["analyst", "executor"],
        "current_agent": "analyst",
        "analysis_result": {
            "topic": "Test",
            "summary": "Nguồn chưa đủ chắc chắn.",
            "comparison": [],
            "contradictions": [],
            "recommendation": "Cần thêm dữ liệu.",
            "confidence": 0.2,
        },
        "errors": [],
    })

    assert state["next_agent"] == "final"
    assert state["plan"] == []
    assert "execution_request" not in state


def test_execution_request_error_is_converted_to_final_state():
    with patch("agents.planner._classify_route", return_value="EXECUTE"), \
         patch(
             "agents.planner._build_execution_request",
             side_effect=RuntimeError("structured output failed"),
         ):
        state = planner_node({"user_query": "Tính metric", "errors": []})

    assert state["next_agent"] == "final"
    assert state["plan"] == []
    assert "execution_request_error" in state["errors"][-1]
    assert state["final_answer"]


def test_direct_response_llm_error_does_not_crash_planner():
    with patch("agents.planner._classify_route", return_value="DIRECT_RESPONSE"), \
         patch("agents.planner.get_llm", side_effect=RuntimeError("llm unavailable")):
        state = planner_node({"user_query": "Xin chào", "errors": []})

    assert state["next_agent"] == "final"
    assert "final_answer_error" in state["errors"][-1]
    assert "ERR-PLANNER" in state["final_answer"]
    assert "llm unavailable" not in state["final_answer"]


def test_research_answer_llm_error_does_not_crash_planner():
    document = {
        "document_id": "doc_1",
        "chunk_id": "doc_1_chunk_00",
        "content": "Prompt Injection",
        "source": "unit_test",
        "trust_level": 0.8,
        "similarity_score": 0.9,
    }
    with patch("agents.planner.get_llm", side_effect=RuntimeError("llm unavailable")):
        state = planner_node({
            "user_query": "Prompt Injection là gì?",
            "route": "RESEARCH",
            "plan": ["research"],
            "current_agent": "research",
            "retrieved_documents": [document],
            "errors": [],
        })

    assert state["next_agent"] == "final"
    assert "final_answer_error" in state["errors"][-1]
    assert state["final_answer"]
