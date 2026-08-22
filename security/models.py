"""Schema dùng chung cho các lớp phòng thủ."""

from typing import Any, Literal

from pydantic import BaseModel, Field


SecurityStage = Literal[
    "input",
    "agent_message",
    "retrieval",
    "knowledge_validation",
    "tool_permission",
    "output",
]


class SecurityEvent(BaseModel):
    stage: SecurityStage
    rule: str
    action: Literal["allowed", "observed", "blocked", "filtered", "redacted"]
    detail: str


class GuardResult(BaseModel):
    allowed: bool = True
    value: Any
    events: list[SecurityEvent] = Field(default_factory=list)
