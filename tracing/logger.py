"""
Structured logging cho từng bước Agent (mục 12 của spec).

Log tối thiểu mỗi entry:
    trace_id, timestamp, agent, input, output, route, latency, error

Ghi ra TRACE_OUTPUT_DIR (JSON lines), để sau này phân tích injection
propagation giữa các Agent (mục 14): injection_source, target_agent,
propagated_to, tool_called, final_output_affected.

Sẽ triển khai ở Phase 8.
"""

from __future__ import annotations

import json
import hashlib
import math
import os
import re
import threading
from datetime import UTC, datetime
from itertools import islice
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from tracing.schema import TraceEvent


_WRITE_LOCK = threading.Lock()
MAX_LOG_DEPTH = 8
MAX_LOG_COLLECTION_ITEMS = 100
MAX_LOG_STRING_CHARS = 4_000
DEFAULT_MAX_EVENT_BYTES = 256_000
DEFAULT_MAX_FILE_BYTES = 10_000_000
DEFAULT_BACKUP_COUNT = 5
_SENSITIVE_KEY_PARTS = (
    "api_key",
    "apikey",
    "authorization",
    "password",
    "secret",
    "token",
    "cookie",
    "records",
)
_SECRET_VALUE_PATTERNS = (
    re.compile(r"\bAIza[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._-]{8,}\b", re.IGNORECASE),
    re.compile(
        r"\b(?:api[_ -]?key|password|passwd|secret|access[_ -]?token|"
        r"refresh[_ -]?token|authorization)\b\s*[:=]\s*"
        r"(?:Bearer\s+)?[^\s,;]+",
        re.IGNORECASE,
    ),
)


def _is_sensitive_key(key: Any) -> bool:
    normalized = str(key).strip().lower()
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _sanitize_string(value: str) -> str:
    truncated = len(value) > MAX_LOG_STRING_CHARS
    visible = value[:MAX_LOG_STRING_CHARS] if truncated else value
    sanitized = visible
    for pattern in _SECRET_VALUE_PATTERNS:
        sanitized = pattern.sub("[REDACTED]", sanitized)
    if not truncated:
        return sanitized
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
    return sanitized + f"...[TRUNCATED sha256={digest}]"


def sanitize_for_log(value: Any) -> Any:
    """Chuyển dữ liệu thành JSON-safe, có redaction và giới hạn kích thước."""
    return _sanitize_for_log(value, depth=0, seen=set())


def _sanitize_for_log(value: Any, *, depth: int, seen: set[int]) -> Any:
    if depth > MAX_LOG_DEPTH:
        return "[MAX_DEPTH_REACHED]"
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    if isinstance(value, dict):
        identity = id(value)
        if identity in seen:
            return "[CYCLE_DETECTED]"
        seen.add(identity)
        try:
            result = {}
            for key, item in islice(value.items(), MAX_LOG_COLLECTION_ITEMS):
                safe_key = _sanitize_string(str(key))[:200]
                result[safe_key] = (
                    "[REDACTED]"
                    if _is_sensitive_key(key)
                    else _sanitize_for_log(item, depth=depth + 1, seen=seen)
                )
            if len(value) > MAX_LOG_COLLECTION_ITEMS:
                result["[TRUNCATED_ITEMS]"] = len(value) - MAX_LOG_COLLECTION_ITEMS
            return result
        finally:
            seen.remove(identity)
    if isinstance(value, (list, tuple, set)):
        identity = id(value)
        if identity in seen:
            return "[CYCLE_DETECTED]"
        seen.add(identity)
        try:
            result = [
                _sanitize_for_log(item, depth=depth + 1, seen=seen)
                for item in islice(iter(value), MAX_LOG_COLLECTION_ITEMS)
            ]
            if len(value) > MAX_LOG_COLLECTION_ITEMS:
                result.append(
                    f"[TRUNCATED_ITEMS count={len(value) - MAX_LOG_COLLECTION_ITEMS}]"
                )
            return result
        finally:
            seen.remove(identity)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return _sanitize_string(str(value))
    if isinstance(value, bytes):
        return f"<bytes:{len(value)}>"
    if isinstance(value, str):
        return _sanitize_string(value)
    if isinstance(value, float) and not math.isfinite(value):
        return "[NON_FINITE_FLOAT]"
    if value is None or isinstance(value, (int, float, bool)):
        return value
    return _sanitize_string(repr(value))


def _bounded_int_env(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} phải là số nguyên") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} phải nằm trong [{minimum}, {maximum}]")
    return value


def _trace_limits() -> tuple[int, int, int]:
    max_event_bytes = _bounded_int_env(
        "TRACE_MAX_EVENT_BYTES", DEFAULT_MAX_EVENT_BYTES, 512, 5_000_000
    )
    max_file_bytes = _bounded_int_env(
        "TRACE_MAX_FILE_BYTES", DEFAULT_MAX_FILE_BYTES, 512, 1_000_000_000
    )
    backup_count = _bounded_int_env(
        "TRACE_BACKUP_COUNT", DEFAULT_BACKUP_COUNT, 0, 100
    )
    return max_event_bytes, max_file_bytes, backup_count


def get_trace_file() -> Path:
    output_dir = Path(os.environ.get("TRACE_OUTPUT_DIR", "./tracing/logs"))
    filename = os.environ.get("TRACE_FILE_NAME", "agent_trace.jsonl")
    return output_dir / filename


def write_trace_event(event: TraceEvent) -> Path:
    """Append đúng một JSON object trên một dòng và trả đường dẫn log."""
    path = get_trace_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(
        event.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    encoded_size = len((line + "\n").encode("utf-8"))
    max_event_bytes, max_file_bytes, backup_count = _trace_limits()
    if encoded_size > max_event_bytes:
        raise ValueError(
            f"Trace event vượt giới hạn {max_event_bytes} bytes"
        )
    if encoded_size > max_file_bytes:
        raise ValueError(
            f"Trace event lớn hơn TRACE_MAX_FILE_BYTES={max_file_bytes}"
        )
    with _WRITE_LOCK:
        current_size = path.stat().st_size if path.exists() else 0
        if current_size and current_size + encoded_size > max_file_bytes:
            _rotate_trace_file(path, backup_count)
        with path.open("a", encoding="utf-8", newline="\n") as file:
            file.write(line + "\n")
    return path


def _rotate_trace_file(path: Path, backup_count: int) -> None:
    """Rotate file hiện tại, chỉ giữ đúng số backup đã cấu hình."""
    if backup_count == 0:
        path.unlink(missing_ok=True)
        return

    oldest = path.with_name(f"{path.name}.{backup_count}")
    oldest.unlink(missing_ok=True)
    for index in range(backup_count, 0, -1):
        source = path if index == 1 else path.with_name(f"{path.name}.{index - 1}")
        if source.exists():
            source.replace(path.with_name(f"{path.name}.{index}"))


def log_step(
    *,
    trace_id: str,
    sequence: int,
    agent: str,
    input_data: dict,
    output_data: dict,
    route: str | None,
    latency_ms: float,
    error: str | None = None,
    injection_source: str | None = None,
    target_agent: str | None = None,
    propagated_to: list[str] | None = None,
    tool_called: str | None = None,
    final_output_affected: bool | None = None,
    security_events: list[dict] | None = None,
) -> Path:
    """Validate, sanitize và ghi một trace event."""
    event = TraceEvent(
        trace_id=trace_id,
        sequence=sequence,
        timestamp=datetime.now(UTC),
        agent=agent,
        input=sanitize_for_log(input_data),
        output=sanitize_for_log(output_data),
        route=route,
        latency=round(max(0.0, latency_ms) / 1000, 6),
        latency_ms=round(max(0.0, latency_ms), 3),
        error=sanitize_for_log(error) if error is not None else None,
        injection_source=(
            sanitize_for_log(injection_source)
            if injection_source is not None else None
        ),
        target_agent=(
            sanitize_for_log(target_agent) if target_agent is not None else None
        ),
        propagated_to=sanitize_for_log(propagated_to or []),
        tool_called=sanitize_for_log(tool_called) if tool_called is not None else None,
        final_output_affected=final_output_affected,
        security_events=sanitize_for_log(security_events or []),
    )
    return write_trace_event(event)
