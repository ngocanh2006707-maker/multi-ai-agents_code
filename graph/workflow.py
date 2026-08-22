"""
Ghép toàn bộ Agent thành LangGraph StateGraph — Centralized Orchestrator.

Cấu trúc graph mong muốn (xem mục 10 của spec):
    START -> planner
    planner --(conditional_edges qua route_planner)--> research/analyst/executor/END
    research -> planner
    analyst  -> planner
    executor -> planner

QUAN TRỌNG: Không add_edge tuyến tính cố định
(planner -> research -> analyst -> executor cho MỌI câu hỏi).
Mọi worker luôn add_edge quay VỀ planner, không bao giờ trỏ thẳng sang
worker khác (đúng nguyên tắc mục 21: Worker không giao tiếp trực tiếp).

Sẽ triển khai ở Phase 7 (sau khi Planner + Research + Analyst + Executor
đã chạy được độc lập).
"""

from langgraph.graph import END, START, StateGraph

from agents.analyst import analyst_node
from agents.executor import executor_node
from agents.planner import planner_node
from agents.researcher import research_node
from graph.router import route_planner
from graph.state import AgentState, WorkflowInput
from tracing.tracer import traced_node


def build_workflow():
    """Tạo và compile Centralized Orchestrator workflow.

    Mọi Worker chỉ có một outgoing edge quay về Planner. Planner là node duy
    nhất sử dụng conditional edges để chọn Worker tiếp theo hoặc kết thúc.
    """
    # Chỉ nhận public input đã định nghĩa. Nếu caller gửi kèm plan,
    # current_agent hoặc worker result giả, LangGraph sẽ loại các field đó
    # trước node Planner đầu tiên.
    workflow = StateGraph(AgentState, input_schema=WorkflowInput)

    workflow.add_node("planner", traced_node("planner", planner_node))
    workflow.add_node("research", traced_node("research", research_node))
    workflow.add_node("analyst", traced_node("analyst", analyst_node))
    workflow.add_node("executor", traced_node("executor", executor_node))

    workflow.add_edge(START, "planner")
    workflow.add_conditional_edges(
        "planner",
        route_planner,
        {
            "research": "research",
            "analyst": "analyst",
            "executor": "executor",
            "final": END,
        },
    )

    workflow.add_edge("research", "planner")
    workflow.add_edge("analyst", "planner")
    workflow.add_edge("executor", "planner")

    return workflow.compile()
