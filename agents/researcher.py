"""Research Agent — chỉ truy xuất thông tin từ Knowledge Base."""

from __future__ import annotations

from graph.state import AgentState
from knowledge_base.retrieval import search
from security.retrieval_guard import guard_retrieval


def research_node(state: AgentState) -> AgentState:
    """Semantic search và ghi kết quả vào state.

    Research Agent không phân tích, không đưa quyết định cuối cùng và không
    gọi tool hệ thống. Sau node này, workflow phải quay về Planner.
    """
    query = (state.get("research_query") or state.get("user_query") or "").strip()
    top_k = int(state.get("research_top_k", 5))

    try:
        raw_documents = search(query=query, top_k=top_k)
        guard_result = guard_retrieval(raw_documents)
        documents = guard_result.value
        security_events = list(state.get("security_events", []))
        security_events.extend(event.model_dump() for event in guard_result.events)
        result = {
            **state,
            "research_query": query,
            "retrieved_documents": documents,
            "retrieval_filtered_count": len(raw_documents) - len(documents),
            "security_events": security_events,
            "current_agent": "research",
        }
        injection_events = [
            event
            for event in guard_result.events
            if event.rule.startswith("prompt_injection_pattern_")
        ]
        if injection_events:
            metadata = {
                "injection_source": "knowledge_base",
                "target_agent": "research",
                "propagated_to": [],
            }
            if all(event.action == "filtered" for event in injection_events):
                metadata["final_output_affected"] = False
            result.update(metadata)
        return result
    except Exception as exc:
        errors = list(state.get("errors", []))
        errors.append(f"research: {type(exc).__name__}: {exc}")
        return {
            **state,
            "research_query": query,
            "retrieved_documents": [],
            "current_agent": "research",
            "errors": errors,
        }
