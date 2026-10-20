"""Heuristic đa ngôn ngữ để phát hiện Direct Prompt Injection."""

import re
import unicodedata
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import wraps
from typing import Literal


_DETECTION_CACHE: ContextVar[dict | None] = ContextVar("detection_cache", default=None)
_MAX_DETECTION_CACHE_ENTRIES = 256


@contextmanager
def _reuse_detection():
    """Keep pure scan results within one guard call, including nested scans.

    No policy decisions/settings are cached. A new scope owns a fresh cache;
    raw text is released on normal return and on exceptions.
    """
    cache = {}
    token = _DETECTION_CACHE.set(cache)
    try:
        yield
    finally:
        cache.clear()
        _DETECTION_CACHE.reset(token)


def _memoize_detection(function):
    @wraps(function)
    def cached(*args, **kwargs):
        cache = _DETECTION_CACHE.get()
        # Preserve legacy conversion of non-string inputs without caching
        # arbitrary objects or relying on their hash/equality implementations.
        if cache is None or any(type(value) not in (str, type(None)) for value in (*args, *kwargs.values())):
            return function(*args, **kwargs)
        key = (function, args, tuple(sorted(kwargs.items())))
        if key not in cache:
            result = function(*args, **kwargs)
            if len(cache) >= _MAX_DETECTION_CACHE_ENTRIES:
                cache.pop(next(iter(cache)))
            cache[key] = (True, tuple(result)) if isinstance(result, list) else (False, result)
        is_list, result = cache[key]
        # Guard callers may append event rules. Never expose a cached list.
        return list(result) if is_list else result

    return cached


_ZERO_WIDTH_CHARS = re.compile(r"[\u200b-\u200f\u2060\ufeff]")
_WHITESPACE = re.compile(r"\s+")
_RETRIEVAL_FORMAT_PREFIX = re.compile(r"^(?:#{1,6}\s+|[-*+>]\s+|\d+[.)]\s+)")
_RETRIEVAL_ADDRESS_PREFIX = re.compile(
    r"^(?:(?:for|to)\s+(?:the\s+)?(?:assistant|agent|model)|"
    r"(?:note|instructions?)\s+(?:for|to)\s+(?:the\s+)?(?:assistant|agent|model)|"
    r"lưu\s+ý(?:\s+dành\s+cho\s+(?:trợ\s+lý|agent))?|"
    r"(?:system|developer|assistant)(?:\s+override)?)\s*:\s*",
    re.I,
)
_RETRIEVAL_ANSWER_INSTRUCTION = re.compile(
    r"\b(?:(?:for|in)\s+(?:your|the)\s+(?:final\s+)?(?:answer|response)\s*[,:]?\s*"
    r"(?:you\s+(?:must|should)\s+)?(?:output|print|say|include|append|return)\b|"
    r"(?:trong|với)\s+câu\s+trả\s+lời(?:\s+cuối\s+cùng)?\s*[,:]?\s*"
    r"(?:hãy\s+)?(?:in\s+ra|chỉ\s+trả\s+lời|thêm|ghi)\b)",
    re.I,
)
_RETRIEVAL_DESCRIPTION = re.compile(
    r"\b(?:paper|study|article)\b.{0,60}\b(?:describes?|discusses?|explains?|demonstrates?)\b|"
    r"\b(?:attacker|adversary)\s+(?:may|might|can|often)\s+(?:say|write|use)\b|"
    r"\b(?:detector|filter)\b.{0,50}\b(?:flag|detect|recognize)\b|"
    r"\b(?:such\s+as|including\s+(?:the\s+)?phrase)\s*[\"'“‘]|"
    r"\b(?:bài\s+báo|nghiên\s+cứu)\b.{0,60}\b(?:mô\s+tả|thảo\s+luận|giải\s+thích)\b",
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


@dataclass(frozen=True)
class CanonicalizedText:
    """Các biểu diễn an toàn để detector dùng mà không mất input gốc."""

    original: str
    normalized: str
    compact: str


@_memoize_detection
def canonicalize_text(text: str | None) -> CanonicalizedText:
    """Trả về các dạng xem gốc, đã chuẩn hóa và đã bỏ dấu phân cách của detector.

    ``normalized`` keeps word boundaries for the existing multilingual rules.
    ``compact`` removes punctuation, symbols and whitespace so token splitting
    such as ``i-g-n-o-r-e`` cannot bypass a compact rule.  The original value
    is retained for policy-controlled forwarding, never for telemetry detail.
    """

    original = text if isinstance(text, str) else str(text or "")
    normalized = unicodedata.normalize("NFKC", original)
    normalized = _ZERO_WIDTH_CHARS.sub("", normalized)
    normalized = _WHITESPACE.sub(" ", normalized).strip()
    compact = re.sub(r"[^\w]+|_", "", normalized.casefold())
    return CanonicalizedText(
        original=original,
        normalized=normalized,
        compact=compact,
    )


def _normalize_for_detection(text: str) -> str:
    """Dạng xem chuẩn hóa tương thích ngược cho caller/test hiện có."""

    return canonicalize_text(text).normalized


# Các mẫu rút gọn chỉ cố ý mô phỏng những rule có tín hiệu cao. Chúng hoạt động
# trên dạng bỏ dấu phân cách nên bắt được cách tách bằng dấu câu/gạch dưới mà
# không biến văn bản nghiên cứu thông thường thành một kết quả khớp injection.
_COMPACT_INJECTION_RULES: dict[str, re.Pattern[str]] = {
    "en_ignore_instructions": re.compile(
        r"(?:ignore|disregard)(?:all|the)?(?:previous|prior)instructions"
    ),
    "en_reveal_prompt": re.compile(
        r"(?:reveal|show|print|expose)(?:the)?(?:system|developer)prompt"
    ),
    "en_override_instructions": re.compile(
        r"(?:donotfollow(?:the)?(?:system|developer)instructions|"
        r"override(?:the)?(?:system|developer)instructions)"
    ),
    "en_role_hijack": re.compile(r"youarenow"),
}


def _rule_matches(
    rule_name: str,
    pattern: re.Pattern[str],
    canonical: CanonicalizedText,
) -> bool:
    compact_pattern = _COMPACT_INJECTION_RULES.get(rule_name)
    return bool(
        pattern.search(canonical.normalized)
        or (compact_pattern and compact_pattern.search(canonical.compact))
    )


def _compact_retrieval_command(rule_name: str, sentence: str) -> bool:
    """Apply compact matching without treating quoted prose as a command."""

    compact_pattern = _COMPACT_INJECTION_RULES.get(rule_name)
    if compact_pattern is None:
        return False

    canonical = canonicalize_text(sentence)
    normalized = canonical.normalized.casefold()
    positions = [match.start() for match in re.finditer(r"[^\W_]", normalized)]
    return any(
        _is_retrieval_command(normalized, positions[match.start()])
        for match in compact_pattern.finditer(canonical.compact)
    )


def _is_retrieval_command(sentence: str, match_start: int) -> bool:
    """Classify each match by local reporting context, never by start position.

    Unknown prefixes stay suspect. A reporting clause does not exempt a later
    imperative clause in the same sentence; evaluate every match separately.
    """
    prefix = sentence[:match_start].rsplit(",", 1)[-1].strip()
    if re.search(
        r"\b(?:but|however|instead|therefore|and(?:\s+then)?|nhưng|thay\s+vào\s+đó|"
        r"và(?:\s+sau\s+đó)?|(?:you|assistant|agent|model)\s+(?:must|should|shall))\s*$",
        prefix, re.I,
    ):
        return True
    return not _RETRIEVAL_DESCRIPTION.search(prefix)


def retrieval_command_candidates(text: str) -> list[str]:
    """Preserve line/clause boundaries before canonicalization folds whitespace.

    Only strip structural formatting and explicit agent-address prefixes;
    descriptive prose and quotes never gain trust from their own labels.
    """
    segments = re.split(r"[\r\n]+|[;；]\s*|(?<=[.!?。！？])\s+", str(text))
    candidates: list[str] = []
    for segment in segments:
        candidate = canonicalize_text(segment).normalized
        candidate = _RETRIEVAL_FORMAT_PREFIX.sub("", candidate)
        candidate = _RETRIEVAL_ADDRESS_PREFIX.sub("", candidate)
        if candidate:
            candidates.append(candidate)
    return candidates


@_memoize_detection
def detect_injection_patterns(
    text: str,
    context: Literal["user_input", "retrieved_content"] = "user_input",
) -> list[str]:
    """Trả tên rule khớp, với chính sách riêng cho input và nội dung KB."""
    canonical = canonicalize_text(text)
    if context == "user_input":
        return [
            f"prompt_injection_pattern_{rule_name}"
            for rule_name, pattern in _INJECTION_RULES
            if _rule_matches(rule_name, pattern, canonical)
        ]
    if context != "retrieved_content":
        raise ValueError(f"Detection context không hợp lệ: {context!r}")

    sentences = retrieval_command_candidates(text)
    detections = [
        f"prompt_injection_pattern_{rule_name}"
        for rule_name, pattern in _INJECTION_RULES
        if any(
            any(_is_retrieval_command(sentence, match.start()) for match in pattern.finditer(sentence))
            or _compact_retrieval_command(rule_name, sentence)
            for sentence in sentences
        )
    ]
    if any(
        _is_retrieval_command(sentence, match.start())
        for sentence in sentences
        for match in _RETRIEVAL_ANSWER_INSTRUCTION.finditer(sentence)
    ):
        detections.append("prompt_injection_pattern_retrieval_answer_instruction")
    return detections
