"""
test_workflow — sẽ triển khai song song với Agent/module tương ứng
(xem comment trong file agents/*.py, graph/*.py, knowledge_base/*.py).
"""

from unittest.mock import patch

from agents.analyst import analyst_node
from agents.analyst_schema import AnalysisDraft
from agents.executor import executor_node
from agents.planner import planner_node
from agents.researcher import research_node


def test_research_analysis_flow_returns_to_planner_before_final():
    documents = [{
        "document_id": "doc_1",
        "chunk_id": "doc_1_chunk_00",
        "content": "Input Validation kiểm tra đầu vào.",
        "source": "unit_test",
        "trust_level": 0.8,
        "similarity_score": 0.9,
    }]
    llm_result = AnalysisDraft(
        topic="Phòng thủ Prompt Injection",
        summary="Hai lớp phòng thủ bổ trợ cho nhau.",
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
        recommendation="Nên kết hợp nhiều lớp bảo vệ.",
        evidence_document_ids=["doc_1"],
    )

    with patch("agents.planner._classify_route", return_value="RESEARCH_AND_ANALYSIS"), \
         patch("agents.researcher.search", return_value=documents), \
         patch("agents.analyst.get_llm") as mocked_get_llm:
        structured_llm = mocked_get_llm.return_value.with_structured_output.return_value
        structured_llm.invoke.return_value = llm_result

        state = planner_node({
            "user_query": "So sánh Input Validation và Least Privilege"
        })
        assert state["next_agent"] == "research"

        state = research_node(state)
        state = planner_node(state)
        assert state["next_agent"] == "analyst"

        state = analyst_node(state)
        state = planner_node(state)

    assert state["next_agent"] == "final"
    assert state["plan"] == []
    assert "Hai lớp phòng thủ bổ trợ cho nhau." in state["final_answer"]
    assert "Độ tin cậy: 0.64" in state["final_answer"]
    assert "{'topic':" not in state["final_answer"]


def test_execute_flow_returns_structured_result_to_planner():
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
        state = planner_node({"user_query": "Tính Attack Success Rate"})

    assert state["next_agent"] == "executor"
    state = executor_node(state)
    state = planner_node(state)

    assert state["next_agent"] == "final"
    assert state["execution_result"]["status"] == "success"
    assert state["execution_result"]["result"]["value"] == 0.5
    assert "thực thi thành công" in state["final_answer"]
