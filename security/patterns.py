"""Heuristic đa ngôn ngữ để phát hiện Direct Prompt Injection."""

import re
import unicodedata
from typing import Literal


_ZERO_WIDTH_CHARS = re.compile(r"[\u200b-\u200f\u2060\ufeff]")
_WHITESPACE = re.compile(r"\s+")
_SENTENCE_BOUNDARY = re.compile(r"(?<=[.!?。！？])\s+")
_POLITE_COMMAND_PREFIX = re.compile(
    r"^(?:please|hãy|vui\s+lòng|por\s+favor|s['’]il\s+vous\s+pla[iî]t|"
    r"bitte|por\s+favor|пожалуйста)\s*[:,]?\s*$",
    re.I,
)

# Mỗi rule có tên ổn định để trace cho biết ngôn ngữ và loại tấn công.
# Các biểu thức tập trung vào hai ý định rủi ro cao: vô hiệu hóa chỉ dẫn trước đó
# và yêu cầu tiết lộ system/developer prompt.
_INJECTION_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "en_ignore_instructions",
        re.compile(
            r"\b(?:ignore|disregard)\s+(?:(?:all|the)\s+)?"
            r"(?:previous|prior)\s+instructions?\b",
            re.I,
        ),
    ),
    (
        "en_reveal_prompt",
        re.compile(
            r"\b(?:reveal|show|print|expose)\s+(?:the\s+)?"
            r"(?:system|developer)\s+prompt\b",
            re.I,
        ),
    ),
    (
        "en_override_instructions",
        re.compile(
            r"\b(?:do\s+not\s+follow|override)\s+(?:the\s+)?"
            r"(?:system|developer)\s+instructions?\b",
            re.I,
        ),
    ),
    ("en_role_hijack", re.compile(r"\byou\s+are\s+now\b", re.I)),
    (
        "vi_ignore_instructions",
        re.compile(
            r"\b(?:bỏ\s+qua|phớt\s+lờ|lờ\s+đi|không\s+tuân\s+theo)\b"
            r".{0,80}?\b(?:chỉ\s+dẫn|hướng\s+dẫn|mệnh\s+lệnh)\b",
            re.I,
        ),
    ),
    (
        "vi_reveal_prompt",
        re.compile(
            r"\b(?:tiết\s+lộ|hiển\s+thị|in\s+ra|cho\s+(?:tôi|ta)\s+xem)\b"
            r".{0,80}?\b(?:system|developer|hệ\s+thống|nhà\s+phát\s+triển)"
            r"\s*prompt\b",
            re.I,
        ),
    ),
    (
        "vi_override_instructions",
        re.compile(
            r"\b(?:ghi\s+đè|vô\s+hiệu(?:\s+hóa)?|không\s+làm\s+theo)\b"
            r".{0,80}?\b(?:chỉ\s+dẫn|hướng\s+dẫn|mệnh\s+lệnh)\b",
            re.I,
        ),
    ),
    (
        "es_ignore_instructions",
        re.compile(
            r"\b(?:ignora|ignore|desobedece)\b.{0,60}?"
            r"\b(?:instrucciones|indicaciones)\s+(?:anteriores|previas)\b",
            re.I,
        ),
    ),
    (
        "es_reveal_prompt",
        re.compile(
            r"\b(?:revela|muestra|imprime)\b.{0,50}?"
            r"\bprompt\s+(?:del\s+)?sistema\b",
            re.I,
        ),
    ),
    (
        "fr_ignore_instructions",
        re.compile(
            r"\b(?:ignore|ignorez)\b.{0,60}?"
            r"\b(?:instructions|consignes)\s+(?:précédentes|antérieures)\b",
            re.I,
        ),
    ),
    (
        "fr_reveal_prompt",
        re.compile(
            r"\b(?:révèle|révélez|affiche|affichez)\b.{0,50}?"
            r"\bprompt\s+(?:du\s+)?système\b",
            re.I,
        ),
    ),
    (
        "de_ignore_instructions",
        re.compile(
            r"\b(?:ignoriere|ignorieren\s+sie)\b.{0,60}?"
            r"\b(?:vorherigen|früheren)\s+anweisungen\b",
            re.I,
        ),
    ),
    (
        "de_reveal_prompt",
        re.compile(
            r"\b(?:zeige|zeigen\s+sie|enthülle)\b.{0,50}?"
            r"\b(?:systemprompt|system\s*prompt)\b",
            re.I,
        ),
    ),
    (
        "pt_ignore_instructions",
        re.compile(
            r"\b(?:ignore|desconsidere)\b.{0,60}?"
            r"\b(?:instruções|orientações)\s+(?:anteriores|prévias)\b",
            re.I,
        ),
    ),
    (
        "pt_reveal_prompt",
        re.compile(
            r"\b(?:revele|mostre|imprima)\b.{0,50}?"
            r"\bprompt\s+(?:do\s+)?sistema\b",
            re.I,
        ),
    ),
    (
        "ru_ignore_instructions",
        re.compile(
            r"\b(?:игнорируй|игнорируйте)\b.{0,60}?"
            r"\bпредыдущие\s+инструкции\b",
            re.I,
        ),
    ),
    (
        "ru_reveal_prompt",
        re.compile(
            r"\b(?:покажи|раскрой|раскройте)\b.{0,50}?"
            r"\bсистемн(?:ый|ого)\s+(?:промпт|запрос)\b",
            re.I,
        ),
    ),
    (
        "zh_ignore_instructions",
        re.compile(r"(?:忽略|无视|無視).{0,30}?(?:之前|先前|以前).{0,15}?(?:指令|指示)"),
    ),
    (
        "zh_reveal_prompt",
        re.compile(r"(?:显示|顯示|泄露|洩露|透露).{0,30}?(?:系统|系統)提示(?:词|詞)?"),
    ),
    (
        "ja_ignore_instructions",
        re.compile(r"(?:以前|前|これまで).{0,20}?(?:指示|命令).{0,12}?(?:無視|無効)"),
    ),
    (
        "ja_reveal_prompt",
        re.compile(r"システムプロンプト.{0,20}?(?:表示|開示|公開)"),
    ),
    (
        "ko_ignore_instructions",
        re.compile(r"(?:이전|기존).{0,20}?(?:지시|명령).{0,12}?(?:무시|따르지)"),
    ),
    (
        "ko_reveal_prompt",
        re.compile(r"시스템\s*프롬프트.{0,20}?(?:공개|표시|보여)"),
    ),
)

# Giữ API cũ cho module hoặc test bên ngoài đang import biến này.
INJECTION_PATTERNS = tuple(pattern for _, pattern in _INJECTION_RULES)


def _normalize_for_detection(text: str) -> str:
    """Chuẩn hóa Unicode và loại ký tự zero-width thường dùng để né regex."""
    normalized = unicodedata.normalize("NFKC", text or "")
    normalized = _ZERO_WIDTH_CHARS.sub("", normalized)
    return _WHITESPACE.sub(" ", normalized).strip()


def _is_retrieval_command(sentence: str, match: re.Match[str]) -> bool:
    """Chỉ coi pattern trong KB là lệnh nếu nó mở đầu một câu độc lập."""
    prefix = sentence[:match.start()].strip()
    return not prefix or bool(_POLITE_COMMAND_PREFIX.fullmatch(prefix))


def detect_injection_patterns(
    text: str,
    context: Literal["user_input", "retrieved_content"] = "user_input",
) -> list[str]:
    """Trả tên rule khớp, với chính sách riêng cho input và nội dung KB."""
    normalized = _normalize_for_detection(text)
    if context == "user_input":
        return [
            f"prompt_injection_pattern_{rule_name}"
            for rule_name, pattern in _INJECTION_RULES
            if pattern.search(normalized)
        ]
    if context != "retrieved_content":
        raise ValueError(f"Detection context không hợp lệ: {context!r}")

    sentences = _SENTENCE_BOUNDARY.split(normalized)
    return [
        f"prompt_injection_pattern_{rule_name}"
        for rule_name, pattern in _INJECTION_RULES
        if any(
            (match := pattern.search(sentence)) is not None
            and _is_retrieval_command(sentence, match)
            for sentence in sentences
        )
    ]
