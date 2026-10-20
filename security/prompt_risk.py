"""Chấm điểm rủi ro prompt tổng hợp cho T02.

Module này chỉ đánh giá prompt. Quyết định policy và ánh xạ điểm sang mức độ
thuộc các tác vụ tích hợp sau, nên kết quả cố ý không có trường ``risk_level``.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from security.config import SecuritySettings, load_security_settings
from security.patterns import canonicalize_text, detect_injection_patterns, retrieval_command_candidates


SignalName = Literal[
    "override",
    "internal_target",
    "sensitive_action",
    "roleplay",
    "authority_claim",
    "obfuscation",
    "tool_intent",
]

RiskContext = Literal["user_input", "retrieved_content"]

AttackType = Literal[
    "prompt_injection",
    "prompt_exfiltration",
    "indirect_injection",
    "tool_manipulation",
    "none",
]


class RiskAssessment(BaseModel):
    """Stable T02 output; thresholds are intentionally not applied here."""

    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)

    score: float = Field(ge=0.0, le=1.0)
    attack_type: AttackType
    signals: list[SignalName] = Field(default_factory=list)
    sensitive_target: str | None = None


_OVERRIDE_PATTERNS = (
    re.compile(
        r"\b(?:ignore|disregard)\s+(?:(?:all|the)\s+)?"
        r"(?:previous|prior)\s+instructions?\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:override|do\s+not\s+follow)\s+(?:the\s+)?"
        r"(?:system|developer)\s+instructions?\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:bỏ\s+qua|phớt\s+lờ|ghi\s+đè|vô\s+hiệu(?:\s+hóa)?)"
        r".{0,80}(?:chỉ\s+dẫn|hướng\s+dẫn|mệnh\s+lệnh|quy\s+tắc|"
        r"quy\s+định|trước\s+đó)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bi[\s._-]*g[\s._-]*n[\s._-]*o[\s._-]*r[\s._-]*e\b"
        r".{0,80}(?:previous\s+instructions?|chỉ\s+dẫn|quy\s+tắc|"
        r"quy\s+định|trước\s+đó)\b",
        re.IGNORECASE,
    ),
)

_INTERNAL_TARGET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "system_prompt",
        re.compile(
            r"\b(?:system|developer|internal|hidden)\s+"
            r"(?:prompt|instructions?)\b|\bsystem\s*prompt\b",
            re.IGNORECASE,
        ),
    ),
    (
        "configuration",
        re.compile(
            r"\b(?:config(?:uration)?|settings?)\s+files?\b|"
            r"\.(?:env|ya?ml|json|toml)\b|\bfile\s+cấu\s+hình\b",
            re.IGNORECASE,
        ),
    ),
    (
        "secret",
        re.compile(
            r"\b(?:secret|api\s*key|token|password|credential)s?\b|"
            r"\bmật\s+khẩu\b|\bbí\s+mật\b",
            re.IGNORECASE,
        ),
    ),
    (
        "source_code",
        re.compile(
            r"\b(?:source\s+code|repository|repo|mã\s+nguồn|toàn\s+bộ\s+source)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "database",
        re.compile(
            r"\b(?:database|db|vector\s+db|cơ\s+sở\s+dữ\s+liệu)\b",
            re.IGNORECASE,
        ),
    ),
)

_SENSITIVE_ACTION_PATTERNS = (
    re.compile(
        r"\b(?:reveal|show|print|expose|dump|extract|leak|disclose|"
        r"export|dump|tiết\s+lộ|hiển\s+thị|in\s+ra|xuất\s+ra|"
        r"cho\s+(?:tôi|ta)\s+xem)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:delete|remove|modify|overwrite|execute|send|write|"
        r"xóa|sửa|ghi\s+đè|thực\s+thi|gửi)\b",
        re.IGNORECASE,
    ),
)

_REPORTED_SEND_PREFIX = re.compile(
    r"\b(?:context|data|messages?|dữ\s+liệu|tin\s+nhắn)\s+"
    r"(?:that\s+)?(?:i|tôi|caller)\s+(?:(?:have|đã)\s+)?$",
    re.IGNORECASE,
)

_ROLEPLAY_PATTERN = re.compile(
    r"\b(?:roleplay|role\s*play|pretend|simulate|simulation|ctf|game|"
    r"you\s+are\s+now|giả\s+lập|đóng\s+vai|mô\s+phỏng|trò\s+chơi)\b",
    re.IGNORECASE,
)

_AUTHORITY_PATTERN = re.compile(
    r"\b(?:admin|administrator|authorized|official|"
    r"emergency|urgent|immediately|ban\s+quản\s+trị|quản\s+trị\s+viên|"
    r"khẩn\s+cấp|gấp|ngay\s+lập\s+tức)\b",
    re.IGNORECASE,
)

_TOOL_INTENT_PATTERN = re.compile(
    r"\b(?:call|invoke|run|execute|use|trigger)\s+(?:the\s+)?"
    r"(?:tool|function|command|shell|script|api)\b|"
    r"\b(?:gọi|chạy|thực\s+thi|sử\s+dụng)\s+"
    r"(?:tool|công\s+cụ|lệnh|script|api)\b|"
    r"\b(?:delete|remove|write|modify)\s+(?:the\s+)?file\b",
    re.IGNORECASE,
)

_RETRIEVAL_COMMAND_PREFIX = re.compile(
    r"^(?:please|hãy|vui\s+lòng|por\s+favor|bitte|пожалуйста|"
    r"system\s+override|cảnh\s+báo\s+khẩn\s+cấp)?\s*"
    r"(?:ignore|disregard|reveal|show|print|expose|dump|extract|"
    r"pretend|simulate|roleplay|you\s+are\s+now|"
    r"i[\s._-]*g[\s._-]*n[\s._-]*o[\s._-]*r[\s._-]*e|"
    r"bỏ\s+qua|phớt\s+lờ|ghi\s+đè|vô\s+hiệu(?:\s+hóa)?|"
    r"tiết\s+lộ|hiển\s+thị|in\s+ra|xuất\s+ra|"
    r"cho\s+(?:tôi|ta)\s+xem)\b",
    re.IGNORECASE,
)


def _has_any(patterns: tuple[re.Pattern[str], ...], text: str) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def _retrieval_command_text(text: str) -> str:
    sentences = retrieval_command_candidates(text)
    selected: list[str] = []
    for sentence in sentences:
        candidate = sentence.strip()
        if not candidate:
            continue
        if _RETRIEVAL_COMMAND_PREFIX.search(candidate):
            selected.append(candidate)
            continue
        if detect_injection_patterns(candidate, context="retrieved_content"):
            selected.append(candidate)
    return "\n".join(selected)


def _detect_signals(
    text: str,
    *,
    context: RiskContext = "user_input",
) -> tuple[list[SignalName], str | None]:
    canonical = canonicalize_text(text)
    if context == "retrieved_content":
        command_text = _retrieval_command_text(text)
        if not command_text:
            return [], None
        canonical = canonicalize_text(command_text)
    normalized = canonical.normalized
    signals: list[SignalName] = []

    injection_rules = detect_injection_patterns(canonical.original, context=context)
    if (
        any("ignore_instructions" in rule or "override_instructions" in rule
            or "retrieval_answer_instruction" in rule for rule in injection_rules)
        or _has_any(_OVERRIDE_PATTERNS, normalized)
    ):
        signals.append("override")

    sensitive_target = next(
        (target for target, pattern in _INTERNAL_TARGET_PATTERNS if pattern.search(normalized)),
        None,
    )
    if sensitive_target is not None:
        signals.append("internal_target")

    # In caller queries, a relative clause such as "context tôi gửi" reports
    # data supplied by the caller; it does not instruct an agent to send it.
    # Check every match so a later send command remains visible. KB policy is
    # unchanged: retrieved instructions never gain caller authority.
    if any(
        not (
            context == "user_input"
            and match.group().casefold() in {"send", "gửi"}
            and _REPORTED_SEND_PREFIX.search(normalized[:match.start()])
        )
        for pattern in _SENSITIVE_ACTION_PATTERNS
        for match in pattern.finditer(normalized)
    ):
        signals.append("sensitive_action")

    # Tái sử dụng detector đa ngôn ngữ dùng chung làm bằng chứng ngữ nghĩa.
    # Nhờ đó các rule trích xuất prompt theo từng ngôn ngữ không nằm trong
    # module chấm điểm này.
    if any("reveal_prompt" in rule for rule in injection_rules):
        if "internal_target" not in signals:
            sensitive_target = "system_prompt"
            signals.append("internal_target")
        if "sensitive_action" not in signals:
            signals.append("sensitive_action")

    if _ROLEPLAY_PATTERN.search(normalized):
        signals.append("roleplay")
    if any("role_hijack" in rule for rule in injection_rules):
        if "roleplay" not in signals:
            signals.append("roleplay")

    if _AUTHORITY_PATTERN.search(normalized):
        signals.append("authority_claim")

    if re.search(r"[\u200b-\u200f\u2060\ufeff]", canonical.original) or re.search(
        r"(?i)(?:[a-z][._-]){2,}[a-z]", canonical.original
    ):
        signals.append("obfuscation")

    if _TOOL_INTENT_PATTERN.search(normalized):
        signals.append("tool_intent")

    return signals, sensitive_target


def _attack_type(signals: list[SignalName], sensitive_target: str | None) -> AttackType:
    if not signals:
        return "none"
    if len(signals) == 1 and signals[0] != "override":
        return "none"
    if set(signals).issubset({"roleplay", "authority_claim"}):
        return "none"
    if "tool_intent" in signals and (
        "sensitive_action" in signals or "override" in signals or "authority_claim" in signals
    ):
        return "tool_manipulation"
    if sensitive_target is not None and "sensitive_action" in signals:
        return "prompt_exfiltration"
    return "prompt_injection"


def assess_prompt_risk(
    text: str,
    *,
    settings: SecuritySettings | None = None,
    context: RiskContext = "user_input",
) -> RiskAssessment:
    """Đánh giá tín hiệu prompt tổng hợp bằng trọng số từ SecuritySettings."""

    active_settings = settings or load_security_settings()
    signals, sensitive_target = _detect_signals(text, context=context)
    weights = active_settings.prompt_risk_weights
    score = min(
        1.0,
        sum(max(0.0, float(weights.get(signal, 0.0))) for signal in signals),
    )
    return RiskAssessment(
        score=score,
        attack_type=_attack_type(signals, sensitive_target),
        signals=signals,
        sensitive_target=sensitive_target,
    )


# Alias tường minh cho caller thích dùng động từ chấm điểm.
score_prompt_risk = assess_prompt_risk
