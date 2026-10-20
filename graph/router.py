"""
Logic điều hướng (routing) cho conditional_edges của LangGraph.

route_planner(state) là hàm THUẦN: chỉ đọc state["next_agent"], không gọi
LLM, không side-effect. Planner đã set sẵn next_agent trước khi hàm này
được gọi.
"""

from graph.state import AgentState

# Ánh xạ next_agent (do Planner đặt) -> tên node trong graph.
_ROUTE_MAP = {
    "research": "research",
    "analyst": "analyst",
    "executor": "executor",
    "final": "final",
}


def route_planner(state: AgentState) -> str:
    """Trả về key để LangGraph add_conditional_edges biết node nào chạy tiếp.

    Raises:
        ValueError: nếu next_agent không nằm trong các giá trị hợp lệ
            (fail loudly thay vì âm thầm rơi vào nhánh sai).
    """
    next_agent = state.get("next_agent")
    if next_agent not in _ROUTE_MAP:
        raise ValueError(
            f"next_agent không hợp lệ: {next_agent!r}. "
            f"Giá trị hợp lệ: {list(_ROUTE_MAP.keys())}"
        )
    return _ROUTE_MAP[next_agent]
