"""Chạy thử Phase 6: Planner -> Executor -> Planner -> Final."""

import sys

from dotenv import load_dotenv

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

load_dotenv()

from agents.executor import executor_node
from agents.planner import planner_node


TEST_QUERY = """
Trong thí nghiệm bảo mật AI Agent, hãy tính attack_success_rate từ file
experiments/phase6_attack_results.jsonl trong thư mục data/.
""".strip()


def main() -> None:
    state = {
        "user_query": TEST_QUERY,
        "current_agent": None,
        "errors": [],
    }
    history = ["planner"]
    state = planner_node(state)

    if state["next_agent"] != "executor":
        raise RuntimeError(
            f"Planner route sai: route={state.get('route')}, "
            f"next_agent={state.get('next_agent')}"
        )

    print("Execution request:", state.get("execution_request"))
    request = state.get("execution_request") or {}
    if request.get("tool_name") != "calculate_metrics_from_dataset":
        raise AssertionError(
            "Planner phải dùng calculate_metrics_from_dataset cho yêu cầu từ file, "
            f"nhưng nhận {request.get('tool_name')!r}"
        )
    state = executor_node(state)
    execution = state.get("execution_result") or {}
    if execution.get("status") != "success":
        raise AssertionError(f"Executor thất bại: {execution}")
    metric_result = (execution.get("result") or {}).get("metric_result") or {}
    if metric_result.get("metric") != "attack_success_rate":
        raise AssertionError(f"Metric không đúng: {metric_result}")
    if metric_result.get("value") != 0.666667:
        raise AssertionError(f"Giá trị metric không đúng: {metric_result}")

    history.extend(["executor", "planner"])
    state = planner_node(state)

    expected_history = ["planner", "executor", "planner"]
    if history != expected_history or state.get("next_agent") != "final":
        raise AssertionError(
            f"Flow Phase 6 không đúng: history={history}, "
            f"next_agent={state.get('next_agent')!r}"
        )
    if state.get("errors"):
        raise AssertionError(f"Workflow Phase 6 trả lỗi: {state['errors']}")
    if not str(state.get("final_answer", "")).strip():
        raise AssertionError("Planner không tạo final_answer")

    print("Flow:", " -> ".join(history), "-> final")
    print("Route:", state.get("route"))
    print("Execution result:", state.get("execution_result"))
    print("\nFINAL ANSWER:\n", state.get("final_answer", ""))


if __name__ == "__main__":
    main()
