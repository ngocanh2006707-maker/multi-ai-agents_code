"""Chạy thử luồng Phase 5: Planner -> Research -> Planner -> Analyst -> Planner."""

import sys

from dotenv import load_dotenv

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

load_dotenv()

from agents.analyst import analyst_node
from agents.analyst_schema import AnalysisResult
from agents.planner import planner_node
from agents.researcher import research_node
from knowledge_base.vector_store import collection_count


TEST_QUERY = "So sánh Input Validation và Least Privilege để phòng Prompt Injection."


def run_one(user_query: str) -> dict:
    state = {
        "user_query": user_query,
        "current_agent": None,
        "research_top_k": 5,
        "errors": [],
    }
    history = ["planner"]
    state = planner_node(state)

    while state["next_agent"] != "final":
        next_agent = state["next_agent"]
        if next_agent == "research":
            state = research_node(state)
        elif next_agent == "analyst":
            state = analyst_node(state)
        else:
            raise RuntimeError(f"Phase 5 chưa hỗ trợ node: {next_agent}")

        history.extend([next_agent, "planner"])
        state = planner_node(state)

    expected_history = ["planner", "research", "planner", "analyst", "planner"]
    if history != expected_history:
        raise AssertionError(
            f"Flow Phase 5 không đúng: expected={expected_history}, actual={history}"
        )
    if state.get("route") != "RESEARCH_AND_ANALYSIS":
        raise AssertionError(f"Route Phase 5 không đúng: {state.get('route')!r}")
    if state.get("errors"):
        raise AssertionError(f"Workflow Phase 5 trả lỗi: {state['errors']}")

    analysis = AnalysisResult.model_validate(state.get("analysis_result"))
    defenses = {item.defense.casefold() for item in analysis.comparison}
    if len(defenses) < 2:
        raise AssertionError("Analyst không trả đủ hai biện pháp để so sánh")
    if not analysis.evidence_document_ids:
        raise AssertionError("Analysis không có evidence_document_ids")
    if not str(state.get("final_answer", "")).strip():
        raise AssertionError("Planner không tạo final_answer")

    print("Flow:", " -> ".join(history), "-> final")
    print("Route:", state.get("route"))
    print("\nFINAL ANSWER:\n", state.get("final_answer", ""))
    return state


def main() -> None:
    if collection_count() == 0:
        raise RuntimeError(
            "Vector DB đang rỗng. Hãy chạy: python scripts_build_kb.py --reset"
        )
    run_one(TEST_QUERY)


if __name__ == "__main__":
    main()
