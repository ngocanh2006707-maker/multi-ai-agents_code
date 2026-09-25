"""Schema dùng chung cho các lớp phòng thủ.

Security events are deliberately metadata-only.  Callers may attach a trace
identifier and safe document metadata, but raw prompts and secrets do not
belong in this model.
"""

from __future__ import annotations

import os
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


SecurityStage = Literal[
    "input",
    "agent_message",
    "retrieval",
    "knowledge_validation",
    "tool_permission",
    "output",
]

SecurityAttackType = Literal[
    "prompt_injection",
    "prompt_exfiltration",
    "indirect_injection",
    "tool_manipulation",
    "none",
]

SecurityAction = Literal[
    "allowed",
    "observed",
    "restricted",
    "filtered",
    "blocked",
    "redacted",
]

SecurityMode = Literal["on", "off"]


_SECRET_PATTERNS = (
    re.compile(r"\bAIza[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._-]{16,}\b", re.IGNORECASE),
)


def _default_security_mode() -> SecurityMode:
    """Read the current mode without importing the config module.

    ``security.config`` loads this model, so importing it here would create a
    cycle.  Invalid or absent environment values intentionally fall back to
    the non-enforcing mode for telemetry compatibility.
    """

    mode = os.environ.get("DEFENSE_MODE", "off").strip().lower()
    return mode if mode in {"on", "off"} else "off"


def _sanitize_text(value: Any) -> str:
    text = str(value)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


class SecurityEvent(BaseModel):
    model_config = ConfigDict(allow_inf_nan=False)

    stage: SecurityStage
    attack_type: SecurityAttackType = "none"
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    rule: str
    action: SecurityAction
    detail: str
    trace_id: str = "unavailable"
    document_id: str | None = None
    chunk_id: str | None = None
    mode: SecurityMode = Field(default_factory=_default_security_mode)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("detail", mode="before")
    @classmethod
    def sanitize_detail(cls, value: Any) -> str:
        """Prevent obvious credentials from entering telemetry detail."""

        return _sanitize_text(value)


def security_event_to_dict(
    event: SecurityEvent,
    *,
    trace_id: str | None = None,
    mode: SecurityMode | None = None,
    document_id: str | None = None,
    chunk_id: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Serialize an event with safe, request-scoped telemetry context.

    This helper intentionally accepts only identifiers and metadata.  It does
    not accept prompt text, system instructions, or arbitrary payloads.
    """

    updates: dict[str, Any] = {}
    if trace_id:
        updates["trace_id"] = trace_id
    if mode:
        updates["mode"] = mode
    if document_id is not None:
        updates["document_id"] = document_id
    if chunk_id is not None:
        updates["chunk_id"] = chunk_id
    if metadata:
        updates["metadata"] = {**event.metadata, **metadata}

    if not updates:
        return event.model_dump()
    return SecurityEvent.model_validate({**event.model_dump(), **updates}).model_dump()


class GuardResult(BaseModel):
    allowed: bool = True
    value: Any
    events: list[SecurityEvent] = Field(default_factory=list)
