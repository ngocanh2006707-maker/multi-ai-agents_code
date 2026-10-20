"""
State dùng chung cho toàn bộ LangGraph workflow.

Lưu ý thiết kế:
- `plan` hoạt động như một HÀNG ĐỢI: Planner pop phần tử đầu để set
  next_agent. Khi rỗng -> next_agent = "final".
- `current_agent` = agent VỪA chạy xong (None nếu đây là lượt gọi Planner
  đầu tiên cho request này). Planner dùng field này để phân biệt
  "lần đầu nhận câu hỏi" và "vừa nhận kết quả worker".
- Tránh thêm field không cần thiết (mục 18: hạn chế coupling, giữ đơn giản).

Sẽ triển khai ở Phase 3 (cùng lúc với Planner).
"""

from typing import Any, Literal, TypedDict, Optional

from graph.routes import Route


AgentName = Literal["research", "analyst", "executor", "final"]


class RequiredAgentState(TypedDict):
    """Các field bắt buộc khi bắt đầu một workflow."""

    user_query: str


class WorkflowInput(RequiredAgentState, total=False):
    """Dữ liệu công khai duy nhất caller được phép đưa vào compiled graph.

    Các field điều phối như ``plan``, ``current_agent`` và output của Worker
    tuyệt đối không thuộc schema này. LangGraph sẽ loại chúng tại biên input,
    tránh việc caller giả mạo trạng thái nội bộ hoặc bỏ qua Input Guard.
    """

    conversation_context: list[dict[str, Any]]
    execution_input: dict[str, Any] | None


class AgentState(RequiredAgentState, total=False):
    route: Route
    plan: list[str]

    research_query: str
    kb_task: str
    research_top_k: int
    retrieved_documents: list[dict[str, Any]]
    conversation_context: list[dict[str, Any]]
    has_context: bool
    context_message_count: int
    context_character_count: int
    context_digest: str
    context_metadata_discarded: int
    context_boundary_error: str
    allowed_use: Literal["none", "quote_only"]
    domain_status: Literal["supported", "unsupported", "uncertain"]
    source_scope: Literal["kb_only", "caller_only", "both", "ambiguous"]
    scope_certainty: Literal["clear", "uncertain"]
    scope_reason_code: str
    runtime_decision: dict[str, Any]
    runtime_reason_codes: list[str]
    result_envelopes: list[dict[str, Any]]
    omitted_result_ids: list[str]
    caller_quote_message_count: int
    caller_quote_character_count: int
    caller_quote_removed_character_count: int
    caller_quote_truncated: bool

    analysis_result: dict

    execution_request: dict
    execution_input: dict[str, Any] | None
    execution_params_source: str
    execution_destructive: bool
    execution_params_modified: bool
    execution_params_digest: str
    execution_result: dict

    final_answer: str

    current_agent: Optional[AgentName]
    next_agent: AgentName

    errors: list[str]
    trace_id: str
    trace_sequence: int
    canary_id: str
    canary_fingerprint: str
    telemetry_failed: bool
    telemetry_errors: list[str]

    injection_source: str
    target_agent: str
    propagated_to: list[str]
    tool_called: str
    final_output_affected: bool | None

    # Các bản ghi SecurityEvent đã tuần tự hóa. Bản ghi mới dùng schema
    # telemetry chuẩn hóa; giữ dạng dict để bảo toàn ranh giới LangGraph.
    security_events: list[dict[str, Any]]
    input_blocked: bool
    retrieval_filtered_count: int
