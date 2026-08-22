"""
Vị trí phòng thủ: User Input -> [Input Defense] -> Planner (mục 13).

Khi defense_off: phát hiện ở chế độ monitor-only và trả input nguyên trạng.
Khi defense_on: phát hiện và chặn Direct Prompt Injection pattern cơ bản.

Sẽ triển khai khung tối thiểu ở Phase 9.
"""

from security.config import load_security_settings
from security.models import GuardResult, SecurityEvent
from security.patterns import detect_injection_patterns


def guard_input(user_query: str) -> GuardResult:
    """Luôn phát hiện injection; chỉ block khi policy đang được bật."""
    settings = load_security_settings()
    detections = detect_injection_patterns(user_query)
    if not detections:
        return GuardResult(allowed=True, value=user_query)

    enforce = settings.defense_enabled and settings.input_guard
    return GuardResult(
        allowed=not enforce,
        value=user_query,
        events=[
            SecurityEvent(
                stage="input",
                rule=rule,
                action="blocked" if enforce else "observed",
                detail=(
                    "Phát hiện và chặn chỉ dẫn có dấu hiệu Prompt Injection."
                    if enforce
                    else "Phát hiện chỉ dẫn có dấu hiệu Prompt Injection; policy không chặn."
                ),
            )
            for rule in detections
        ],
    )
