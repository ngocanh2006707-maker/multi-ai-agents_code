"""Research Agent — chỉ truy xuất thông tin từ Knowledge Base."""

from __future__ import annotations

from graph.state import AgentState
from knowledge_base.retrieval import search_candidates as search
from security.models import security_event_to_dict
from security.coordination_guard import safe_error
from security.retrieval_guard import guard_retrieval


def research_node(state: AgentState) -> AgentState:
    """Semantic search và ghi kết quả vào state.

    Research Agent không phân tích, không đưa quyết định cuối cùng và không
    gọi tool hệ thống. Sau node này, workflow phải quay về Planner.
    """
    from security.config import load_security_settings
    if not load_security_settings().defense_enabled:
        from graph.baseline import research_node as baseline_research
        return baseline_research(state)
    query = (state.get("research_query") or state.get("user_query") or "").strip()
    top_k = int(state.get("research_top_k", 5))

    try:
        raw_documents = search(query=query, top_k=top_k)
        guard_result = guard_retrieval(raw_documents)
        # Search returns a bounded pool (3*k), not a prematurely clipped top-k.
        # Keep this local alias so existing search adapters retain their contract.
        documents = guard_result.value[:max(0, top_k)]
        security_events = list(state.get("security_events", []))
        security_events.extend(
            security_event_to_dict(
                event,
                trace_id=state.get("trace_id"),
            )
            for event in guard_result.events
        )
        result = {
            **state,
            "research_query": query,
            "retrieved_documents": documents,
            "retrieval_filtered_count": len(raw_documents) - len(guard_result.value),
            "security_events": security_events,
            "current_agent": "research",
        }
        injection_events = [
            event
            for event in guard_result.events
            if event.stage == "retrieval" and event.attack_type == "indirect_injection"
        ]
        if injection_events:
            metadata = {
                "injection_source": "knowledge_base",
                "target_agent": "research",
                "propagated_to": [],
                "final_output_affected": None,
            }
            result.update(metadata)
        return result
    except Exception as exc:
        errors = list(state.get("errors", []))
        errors.append(safe_error("research", "retrieval_error", exc))
        return {
            **state,
            "research_query": query,
            "retrieved_documents": [],
            "current_agent": "research",
            "errors": errors,
        }
