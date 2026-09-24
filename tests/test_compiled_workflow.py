"""Integration tests trực tiếp trên compiled LangGraph workflow."""

from unittest.mock import MagicMock, patch

from agents.analyst_schema import AnalysisDraft
from graph.workflow import build_workflow


def _document():
    return {
        "document_id": "doc_1",
        "chunk_id": "doc_1_chunk_00",
        "title": "Prompt Injection",
        "source": "unit_test",
        "content": "Prompt Injection là một rủi ro đối với AI Agent.",
        "trust_level": 0.8,
        "similarity_score": 0.9,
    }


def test_compiled_graph_research_route_calls_only_research_worker():
    answer_llm = MagicMock()
    answer_llm.invoke.return_value.content = "Câu trả lời từ Knowledge Base."

    with patch("agents.planner._classify_route", return_value="RESEARCH"), \
         patch("agents.researcher.search", return_value=[_document()]) as search, \
         patch("agents.planner.get_llm", return_value=answer_llm), \
         patch("agents.analyst.get_llm") as analyst_llm:
        result = build_workflow().invoke({
            "user_query": "Direct Prompt Injection là gì?",
            "errors": [],
        })

    assert result["next_agent"] == "final"
    assert result["current_agent"] == "research"
    assert result["final_answer"].startswith("Câu trả lời từ Knowledge Base.")
    assert "Top-K kết quả truy xuất (K=5, hiển thị 1)" in result["final_answer"]
    assert "Prompt Injection" in result["final_answer"]
    assert "Nguồn: unit_test" in result["final_answer"]
    assert "Similarity: 0.9000 | Trust: 0.8000" in result["final_answer"]
    search.assert_called_once()
    analyst_llm.assert_not_called()
    assert "execution_result" not in result


def test_compiled_graph_research_analysis_route():
    analysis = AnalysisDraft(
        topic="So sánh phòng thủ",
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
        "agents.researcher.search", return_value=[_document()]
    ), patch("agents.analyst.get_llm") as analyst_llm:
        structured = analyst_llm.return_value.with_structured_output.return_value
        structured.invoke.return_value = analysis
        result = build_workflow().invoke({
            "user_query": "So sánh Input Validation và Least Privilege",
            "errors": [],
        })

    assert result["next_agent"] == "final"
    assert result["current_agent"] == "analyst"
    assert result["analysis_result"]["topic"] == "So sánh phòng thủ"
    assert "Hai biện pháp bổ trợ nhau." in result["final_answer"]


def test_compiled_graph_execute_route():
    request = {
        "tool_name": "calculate_metrics",
        "params": {
            "metric": "attack_success_rate",
            "records": [
                {"attack_success": True},
                {"attack_success": False},
            ],
        },
    }
    with patch("agents.planner._classify_route", return_value="EXECUTE"), \
         patch("agents.planner._build_execution_request", return_value=request):
        result = build_workflow().invoke({
            "user_query": "Tính Attack Success Rate",
            "errors": [],
        })

    assert result["current_agent"] == "executor"
    assert result["next_agent"] == "final"
    assert result["execution_result"]["status"] == "success"
    assert result["execution_result"]["result"]["value"] == 0.5


def test_compiled_graph_out_of_scope_does_not_call_workers():
    with patch("agents.planner._classify_route", return_value="OUT_OF_SCOPE"), \
         patch("agents.researcher.search") as search, \
         patch("agents.analyst.get_llm") as analyst_llm:
        result = build_workflow().invoke({
            "user_query": "Giá Bitcoin hôm nay bao nhiêu?",
            "errors": [],
        })

    assert result["next_agent"] == "final"
    assert result["plan"] == []
    search.assert_not_called()
    analyst_llm.assert_not_called()
    assert "execution_result" not in result


def test_compiled_graph_research_analysis_execute_keeps_both_outputs():
    analysis = AnalysisDraft(
        topic="Đánh giá phòng thủ",
        summary="Input Validation làm giảm bề mặt tấn công.",
        comparison=[{
            "defense": "Input Validation",
            "purpose": "Lọc đầu vào",
            "evidence_document_ids": ["doc_1"],
        }],
        contradictions=[],
        recommendation="Áp dụng trước khi chạy thử nghiệm.",
        evidence_document_ids=["doc_1"],
    )
    request = {
        "tool_name": "calculate_metrics",
        "params": {
            "metric": "attack_success_rate",
            "records": [
                {"attack_success": True},
                {"attack_success": False},
            ],
        },
    }

    with patch(
        "agents.planner._classify_route",
        return_value="RESEARCH_ANALYSIS_EXECUTE",
    ), patch(
        "agents.researcher.search", return_value=[_document()]
    ), patch(
        "agents.analyst.get_llm"
    ) as analyst_llm, patch(
        "agents.planner._build_execution_request", return_value=request
    ), patch(
        "agents.executor._execute_tool_isolated",
        return_value={"metric": "attack_success_rate", "value": 0.5},
    ):
        structured = analyst_llm.return_value.with_structured_output.return_value
        structured.invoke.return_value = analysis
        result = build_workflow().invoke({
            "user_query": "Phân tích biện pháp rồi tính attack success rate",
        })

    assert result["next_agent"] == "final"
    assert result["current_agent"] == "executor"
    assert "Input Validation làm giảm bề mặt tấn công." in result["final_answer"]
    assert "calculate_metrics" in result["final_answer"]
    assert '"value": 0.5' in result["final_answer"]


def test_compiled_graph_drops_caller_supplied_internal_state():
    answer_llm = MagicMock()
    answer_llm.invoke.return_value.content = "Câu trả lời thật từ Research."
    injected_result = {
        "status": "success",
        "tool": "attacker_supplied",
        "result": {"text": "FAKE RESULT"},
    }

    with patch("agents.planner._classify_route", return_value="RESEARCH"), \
         patch("agents.researcher.search", return_value=[_document()]), \
         patch("agents.planner.get_llm", return_value=answer_llm):
        result = build_workflow().invoke({
            "user_query": "Direct Prompt Injection là gì?",
            "current_agent": "research",
            "plan": ["research"],
            "errors": ["attacker supplied"],
            "execution_result": injected_result,
        })

    assert result["final_answer"].startswith("Câu trả lời thật từ Research.")
    assert "Top-K kết quả truy xuất" in result["final_answer"]
    assert "execution_result" not in result
    assert not result.get("errors")


def test_compiled_graph_can_start_new_request_from_previous_output():
    answer_llm = MagicMock()
    answer_llm.invoke.return_value.content = "Câu trả lời request đầu."
    app = build_workflow()

    with patch("agents.planner._classify_route", return_value="RESEARCH"), \
         patch("agents.researcher.search", return_value=[_document()]), \
         patch("agents.planner.get_llm", return_value=answer_llm):
        previous = app.invoke({"user_query": "Prompt Injection là gì?"})

    with patch("agents.planner._classify_route", return_value="OUT_OF_SCOPE"):
        result = app.invoke({**previous, "user_query": "Giá Bitcoin?"})

    assert result["route"] == "OUT_OF_SCOPE"
    assert result["next_agent"] == "final"
    assert not result.get("errors")
    assert "ngoài phạm vi" in result["final_answer"]


def test_compiled_graph_has_only_centralized_orchestrator_edges():
    edges = {
        (edge.source, edge.target, edge.conditional)
        for edge in build_workflow().get_graph().edges
    }
    assert edges == {
        ("__start__", "planner", False),
        ("planner", "research", True),
        ("planner", "analyst", True),
        ("planner", "executor", True),
        ("planner", "__end__", True),
        ("research", "planner", False),
        ("analyst", "planner", False),
        ("executor", "planner", False),
    }
