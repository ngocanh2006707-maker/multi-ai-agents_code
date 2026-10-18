"""Acceptance phase phát triển 7; CLI gọi model/KB thật, pytest dùng stubs."""

import sys
from copy import deepcopy


TEST_CASES = [
    ({"user_query": "Direct Prompt Injection là gì?"}, "RESEARCH", "research", 4),
    (
        {"user_query": "So sánh Input Validation và Least Privilege để phòng Prompt Injection."},
        "RESEARCH_AND_ANALYSIS",
        "analyst",
        6,
    ),
    ({
        "user_query": (
            "Tính attack_success_rate từ records: "
            '[{"attack_success": true}, {"attack_success": false}]'
        ),
        "execution_input": {
            "tool_name": "calculate_metrics",
            "params": {
                "metric": "attack_success_rate",
                "records": [{"attack_success": True}, {"attack_success": False}],
            },
        },
    }, "EXECUTE", "executor", 4),
    ({"user_query": "Giá Bitcoin hôm nay bao nhiêu?"}, "OUT_OF_SCOPE", None, 2),
]


def run_acceptance(app) -> list[dict]:
    """Dùng cùng assertions cho workflow thật và workflow có provider stubs."""
    from security.config import load_security_settings
    protected = load_security_settings().defense_enabled
    results = []
    for input_data, expected_route, expected_worker, expected_steps in TEST_CASES:
        expected_steps -= 0 if protected else 1
        print("\n" + "=" * 80)
        print("QUERY:", input_data["user_query"])
        result = app.invoke(deepcopy(input_data))
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
        if protected and expected_route == "RESEARCH_AND_ANALYSIS":
            assert any(
                e.get("producer") == "analyst" and e.get("channel") == "kb"
                for e in result.get("result_envelopes", [])
            ), "Workflow không có kết quả Analyst được chấp nhận vào kênh KB"
        if expected_route == "EXECUTE":
            execution = result.get("execution_result") or {}
            assert execution.get("status") == "success", f"Tool không thành công: {execution}"
            assert execution.get("tool") == input_data["execution_input"]["tool_name"]
        results.append(result)

    print("\nDevelopment phase 7 acceptance: PASS")
    return results


def main() -> None:
    from dotenv import load_dotenv

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    load_dotenv()
    from graph.workflow import build_workflow
    from knowledge_base.vector_store import collection_count

    if collection_count() == 0:
        raise SystemExit("Vector DB đang rỗng. Hãy build KB trước khi chạy acceptance thật.")
    run_acceptance(build_workflow())


if __name__ == "__main__":
    main()
