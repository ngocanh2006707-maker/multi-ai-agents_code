"""Acceptance test dùng compiled LangGraph workflow và Agent thật."""

import sys

from dotenv import load_dotenv

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

load_dotenv()

from graph.workflow import build_workflow
from knowledge_base.vector_store import collection_count


TEST_CASES = [
    ("Direct Prompt Injection là gì?", "RESEARCH", "research", 3),
    (
        "So sánh Input Validation và Least Privilege để phòng Prompt Injection.",
        "RESEARCH_AND_ANALYSIS",
        "analyst",
        5,
    ),
    ((
        "Tính attack_success_rate từ records: "
        '[{"attack_success": true}, {"attack_success": false}]'
    ), "EXECUTE", "executor", 3),
    ("Giá Bitcoin hôm nay bao nhiêu?", "OUT_OF_SCOPE", None, 1),
]


def main() -> None:
    if collection_count() == 0:
        raise SystemExit(
            "Vector DB đang rỗng. Hãy chạy: python scripts_build_kb.py --reset"
        )

    app = build_workflow()
    for query, expected_route, expected_worker, expected_steps in TEST_CASES:
        print("\n" + "=" * 80)
        print("QUERY:", query)
        result = app.invoke({"user_query": query})
        print("ROUTE:", result.get("route"))
        print("LAST WORKER:", result.get("current_agent"))
        print("FINAL:\n", result.get("final_answer"))
        if result.get("errors"):
            print("ERRORS:", result["errors"])

        assert result.get("route") == expected_route, (
            f"Sai route: expected={expected_route!r}, actual={result.get('route')!r}"
        )
        assert result.get("current_agent") == expected_worker, (
            "Sai worker cuối: "
            f"expected={expected_worker!r}, actual={result.get('current_agent')!r}"
        )
        assert result.get("trace_sequence") == expected_steps, (
            "Sai số bước graph: "
            f"expected={expected_steps}, actual={result.get('trace_sequence')!r}"
        )
        assert result.get("final_answer"), "Workflow không tạo final_answer"
        assert not result.get("errors"), f"Workflow có lỗi: {result.get('errors')}"

    print("\nPhase 7 acceptance: PASS")


if __name__ == "__main__":
    main()
