"""
Vị trí phòng thủ: Final Output -> [Output Validation] (mục 13).
Executor -> [Tool Permission Defense] cũng thuộc phạm vi module này
hoặc tools/registry.py tuỳ cách bạn tách.

Khi defense_off: phát hiện ở chế độ monitor-only nhưng không redaction.
Khi defense_on: phát hiện và redaction secret trước khi trả kết quả.

Sẽ triển khai khung tối thiểu ở Phase 9.
"""

from __future__ import annotations

import re

from security.config import load_security_settings
from security.models import GuardResult, SecurityEvent


SECRET_PATTERNS = (
    re.compile(r"\bAIza[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._-]{16,}\b", re.IGNORECASE),
)


def guard_output(final_answer: str) -> GuardResult:
    """Luôn phát hiện secret; chỉ redaction khi policy đang được bật."""
    settings = load_security_settings()
    enforce = settings.defense_enabled and settings.output_guard
    sanitized = final_answer
    events: list[SecurityEvent] = []
    for index, pattern in enumerate(SECRET_PATTERNS, start=1):
        if enforce:
            sanitized, count = pattern.subn("[REDACTED]", sanitized)
        else:
            count = len(pattern.findall(sanitized))
        if count:
            events.append(SecurityEvent(
                stage="output",
                rule=f"secret_pattern_{index}",
                action="redacted" if enforce else "observed",
                detail=(
                    f"Đã che {count} giá trị nhạy cảm trong final output."
                    if enforce
                    else f"Phát hiện {count} giá trị nhạy cảm; policy không che."
                ),
            ))

    return GuardResult(allowed=True, value=sanitized, events=events)
