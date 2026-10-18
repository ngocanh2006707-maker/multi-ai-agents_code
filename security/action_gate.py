"""Action Gate theo context cho các lần gọi tool của Executor."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from security.config import SecuritySettings, load_security_settings
from tools.registry import is_allowed


GateAction = Literal["allowed", "observed", "blocked"]


@dataclass(frozen=True)
class ExecutionApprovalRequest:
    """Immutable, concrete request presented to the trusted application callback."""

    run_id: str
    tool_name: str
    params_digest: str
    params_json: str


class ActionGateDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    action: GateAction
    rule: str
    reason_code: str
    destructive: bool = False
    requires_approval: bool = False


_READ_ONLY_TOOLS = {
    "read_dataset",
    "calculate_metrics",
    "calculate_metrics_from_dataset",
    "run_security_test",
}
_DESTRUCTIVE_TOOLS = {"save_test_result"}

_TOOL_QUERY_TERMS: dict[str, frozenset[str]] = {
    "read_dataset": frozenset(
        {"read", "dataset", "file", "data", "csv", "json", "đọc", "tập dữ liệu"}
    ),
    "calculate_metrics": frozenset(
        {"metric", "metrics", "calculate", "compute", "rate", "tính", "đo lường"}
    ),
    "calculate_metrics_from_dataset": frozenset(
        {"metric", "metrics", "calculate", "dataset", "file", "tính", "dữ liệu"}
    ),
    "run_security_test": frozenset(
        {"security", "test", "attack", "defense", "kiểm thử", "bảo mật"}
    ),
    "save_test_result": frozenset(
        {"save", "store", "write", "result", "lưu", "ghi", "kết quả"}
    ),
}


def _normalized_source(value: Any) -> str:
    return str(value or "").strip().casefold().replace("-", "_")


def _is_retrieved_source(source: str) -> bool:
    return source in {
        "retrieved",
        "retrieved_content",
        "retrieved_document",
        "knowledge_base",
        "document",
    }


def _tool_matches_query(user_query: str, tool_name: str) -> bool:
    terms = _TOOL_QUERY_TERMS.get(tool_name)
    if not terms:
        return False
    query = user_query.casefold()
    return any(term in query for term in terms)


def params_digest(params: dict[str, Any]) -> str:
    """Tạo fingerprint cho params đã kiểm tra mà không giữ nội dung thô."""

    encoded = json.dumps(
        params,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def evaluate_action_gate(
    *,
    user_query: str | None,
    tool_name: str,
    params: dict[str, Any],
    params_source: str | None = None,
    approval: bool | None = None,
    destructive: bool | None = None,
    params_modified: bool | None = None,
    expected_params_digest: str | None = None,
    confirmed_request: dict[str, Any] | None = None,
    settings: SecuritySettings | None = None,
) -> ActionGateDecision:
    """Evaluate context without executing a tool or trusting retrieved text."""

    active = settings or load_security_settings()
    normalized_tool = str(tool_name or "").strip()
    source = _normalized_source(params_source)
    is_destructive = normalized_tool in _DESTRUCTIVE_TOOLS or bool(destructive)
    needs_approval = is_destructive

    # Allowlist luôn là lớp kiểm soát bắt buộc trong cả hai chế độ Defense.
    if not normalized_tool or not is_allowed(normalized_tool):
        return ActionGateDecision(
            allowed=False,
            action="blocked",
            rule="action_gate_allowlist",
            reason_code="tool_not_allowlisted",
            destructive=is_destructive,
            requires_approval=needs_approval,
        )

    if not active.action_gate_enabled:
        return ActionGateDecision(
            allowed=True,
            action="allowed",
            rule="action_gate_disabled",
            reason_code="disabled",
            destructive=is_destructive,
            requires_approval=needs_approval,
        )

    reasons: list[str] = []
    if active.action_gate_require_provenance:
        if not source:
            reasons.append("missing_params_provenance")
        elif _is_retrieved_source(source):
            reasons.append("params_from_retrieved_content")
        elif source not in {"user", "caller_task", "planner"}:
            reasons.append("unrecognized_params_provenance")

    # A model's self-digest only detects later changes. Bind the candidate to
    # the schema-validated caller task captured before any model/worker runs.
    if confirmed_request is None:
        reasons.append("missing_confirmed_execution_input")
    else:
        if confirmed_request["tool_name"] != normalized_tool:
            reasons.append("caller_task_tool_mismatch")
        if params_digest(confirmed_request["params"]) != params_digest(params):
            reasons.append("caller_task_params_mismatch")

    if params_modified is True:
        reasons.append("params_modified_after_planning")
    if expected_params_digest:
        if params_digest(params) != str(expected_params_digest).strip().casefold():
            reasons.append("params_integrity_mismatch")

    query = str(user_query or "").strip()
    if not query:
        reasons.append("missing_user_query")
    elif not _tool_matches_query(query, normalized_tool):
        reasons.append("tool_query_mismatch")

    if needs_approval and approval is not True:
        reasons.append("approval_required")

    if reasons:
        enforcing = active.defense_enabled
        return ActionGateDecision(
            allowed=not enforcing,
            action="blocked" if enforcing else "observed",
            rule="action_gate_context",
            reason_code=";".join(reasons),
            destructive=is_destructive,
            requires_approval=needs_approval,
        )

    return ActionGateDecision(
        allowed=True,
        action="allowed",
        rule="action_gate_context",
        reason_code="approved_context",
        destructive=is_destructive,
        requires_approval=needs_approval,
    )


check_action_gate = evaluate_action_gate
