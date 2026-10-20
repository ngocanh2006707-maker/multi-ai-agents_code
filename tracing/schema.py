"""Schema của sự kiện trace có cấu trúc."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


TraceAgent = Literal[
    "context_boundary",
    "planner",
    "research",
    "analyst",
    "executor",
]


class TraceEvent(BaseModel):
    """Một lần thực thi node trong LangGraph."""

    trace_id: str = Field(min_length=1)
    sequence: int = Field(ge=1)
    timestamp: datetime
    agent: TraceAgent
    input: dict[str, Any] = Field(default_factory=dict)
    output: dict[str, Any] = Field(default_factory=dict)
    route: str | None = None
    latency: float = Field(ge=0.0, description="Latency tính bằng giây.")
    latency_ms: float = Field(ge=0.0)
    error: str | None = None
    injection_source: str | None = None
    target_agent: str | None = None
    propagated_to: list[str] = Field(default_factory=list)
    tool_called: str | None = None
    final_output_affected: bool | None = None
    security_events: list[dict[str, Any]] = Field(default_factory=list)
