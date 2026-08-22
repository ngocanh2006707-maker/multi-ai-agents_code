"""Test Phase 4: Planner -> Research -> Planner -> Final.

Trước lần chạy đầu tiên:
    python scripts_build_kb.py --reset

Sau đó:
    python scripts_test_phase4.py
"""

import sys

from dotenv import load_dotenv

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

load_dotenv()

from agents.planner import planner_node
from agents.researcher import research_node
from knowledge_base.vector_store import collection_count


TEST_QUERIES = [
    "Direct Prompt Injection là gì?",
    "Least Privilege giúp giảm tác động của Prompt Injection như thế nào?",
    "Knowledge Poisoning trong RAG có rủi ro gì?",
]

_REQUIRED_RETRIEVAL_FIELDS = {
    "document_id",
    "chunk_id",
    "content",
    "source",
    "timestamp",
    "trust_level",
    "content_hash",
    "similarity_score",
}


def run_one(user_query: str):
    print(f"\n{'=' * 80}\nCâu hỏi: {user_query}\n{'=' * 80}")
    state = {
        "user_query": user_query,
        "current_agent": None,
        "research_top_k": 5,
        "errors": [],
    }

    state = planner_node(state)
    print(f"Planner route     : {state.get('route')}")
    print(f"Planner plan      : {state.get('plan')}")
    print(f"Planner next_agent: {state.get('next_agent')}")

    if state["next_agent"] != "research":
        raise AssertionError(
            "Phase 4 yêu cầu Planner route sang Research, nhưng nhận "
            f"route={state.get('route')!r}, next_agent={state.get('next_agent')!r}"
        )

    state = research_node(state)
    documents = state.get("retrieved_documents", [])
    if state.get("errors"):
        raise AssertionError(f"Research Agent trả lỗi: {state['errors']}")
    if not documents:
        raise AssertionError("Research không trả chunk liên quan nào")

    print(f"Research lấy được: {len(documents)} chunks")
    for i, doc in enumerate(documents, start=1):
        missing = sorted(_REQUIRED_RETRIEVAL_FIELDS - set(doc))
        if missing:
            raise AssertionError(
                f"Chunk {doc.get('chunk_id', i)!r} thiếu field: {missing}"
            )
        if not 0.0 <= float(doc["similarity_score"]) <= 1.0:
            raise AssertionError("similarity_score phải nằm trong [0, 1]")
        print(
            f"  {i}. {doc['chunk_id']} | sim={doc['similarity_score']:.4f} "
            f"| trust={doc['trust_level']:.2f} | {doc.get('title', '')}"
        )

    state = planner_node(state)
    print(f"Planner next_agent sau Research: {state['next_agent']}")
    if state["next_agent"] != "final":
        raise AssertionError(
            "Expected flow Phase 4 là Planner -> Research -> Planner -> Final, "
            f"nhưng next_agent={state['next_agent']!r}"
        )
    if state.get("errors"):
        raise AssertionError(f"Workflow Phase 4 trả lỗi: {state['errors']}")
    if not str(state.get("final_answer", "")).strip():
        raise AssertionError("Planner không tạo final_answer")
    print("\nFINAL ANSWER:\n", state["final_answer"])
    return state


def main():
    if collection_count() == 0:
        raise RuntimeError(
            "Vector DB đang rỗng. Hãy chạy trước:\n"
            "  python scripts_build_kb.py --reset"
        )

    for query in TEST_QUERIES:
        run_one(query)


if __name__ == "__main__":
    main()
