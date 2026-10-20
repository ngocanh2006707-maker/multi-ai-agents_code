"""Trusted boundary and per-run registry for caller-provided context."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import hmac
import json
import re
import secrets
import unicodedata
from typing import Any, Callable, Literal
from uuid import uuid4

from langgraph.runtime import Runtime
from pydantic import BaseModel, ConfigDict, ValidationError, field_validator

from security.coordination_guard import CheckpointRecord, ModelCallRecord, ResultEnvelope
from security.action_gate import ExecutionApprovalRequest


MAX_USER_QUERY_CHARS = 4_000
MAX_CONTEXT_MESSAGES = 20
MAX_CONTEXT_MESSAGE_CHARS = 4_000
MAX_CONTEXT_TOTAL_CHARS = 30_000

AllowedUse = Literal["none", "quote_only"]
DomainStatus = Literal["supported", "unsupported", "uncertain"]
SourceScope = Literal["kb_only", "caller_only", "both", "ambiguous"]
ScopeCertainty = Literal["clear", "uncertain"]


class ContextBoundaryError(ValueError):
    """Public context is invalid or the trusted runtime registry is unavailable."""


class RuntimeRegistryError(RuntimeError):
    """The per-run registry is missing, closed, or accessed by another run."""


class PublicContextMessage(BaseModel):
    """Compatibility schema; role is never treated as provenance."""

    model_config = ConfigDict(extra="ignore")

    content: str
    role: Literal["user", "assistant"] | None = None

    @field_validator("content")
    @classmethod
    def validate_content(cls, value: str) -> str:
        if not isinstance(value, str):
            raise TypeError("content must be a string")
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise ValueError("content contains invalid Unicode") from exc
        normalized = unicodedata.normalize("NFC", value)
        if not normalized.strip():
            raise ValueError("content must not be empty")
        if len(normalized) > MAX_CONTEXT_MESSAGE_CHARS:
            raise ValueError("content exceeds the per-message limit")
        return normalized


@dataclass(frozen=True)
class ContextRecord:
    context_id: str
    source_class: Literal["caller_context"]
    origin_verified: Literal[False]
    content: str
    declared_role: Literal["user", "assistant"] | None


@dataclass(frozen=True)
class RegistrySnapshot:
    run_id: str
    records: tuple[ContextRecord, ...]
    allowed_use: AllowedUse = "none"
    digest: str = ""
    discarded_metadata_fields: int = 0


@dataclass
class RunSourceRegistry:
    run_id: str
    _hmac_key: bytes
    _snapshot: RegistrySnapshot | None = None
    active: bool = True

    def _require_active(self, requester_run_id: str) -> None:
        if not self.active:
            raise RuntimeRegistryError("runtime registry is closed")
        if requester_run_id != self.run_id:
            raise RuntimeRegistryError("runtime registry belongs to another run")

    def initialize(
        self,
        records: tuple[ContextRecord, ...],
        *,
        discarded_metadata_fields: int,
    ) -> RegistrySnapshot:
        self._require_active(self.run_id)
        if self._snapshot is not None:
            raise RuntimeRegistryError("runtime registry is already initialized")
        digest_payload = json.dumps(
            [record.content for record in records],
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        digest = hmac.new(
            self._hmac_key,
            digest_payload,
            hashlib.sha256,
        ).hexdigest()
        self._snapshot = RegistrySnapshot(
            run_id=self.run_id,
            records=records,
            digest=digest,
            discarded_metadata_fields=discarded_metadata_fields,
        )
        return self._snapshot

    def snapshot(self, *, requester_run_id: str) -> RegistrySnapshot:
        self._require_active(requester_run_id)
        if self._snapshot is None:
            raise RuntimeRegistryError("runtime registry is not initialized")
        return self._snapshot

    def set_allowed_use(
        self,
        allowed_use: AllowedUse,
        *,
        requester_run_id: str,
    ) -> RegistrySnapshot:
        snapshot = self.snapshot(requester_run_id=requester_run_id)
        self._snapshot = replace(snapshot, allowed_use=allowed_use)
        return self._snapshot

    def close(self) -> None:
        self._snapshot = None
        self._hmac_key = b""
        self.active = False


@dataclass
class WorkflowRuntimeContext:
    run_id: str
    registry: RunSourceRegistry | None
    original_query: str = ""
    execution_input_json: str = ""
    approval_callback: Callable[[ExecutionApprovalRequest], bool] | None = None
    kb_task: str = ""
    research_dispatched: bool = False
    kb_documents: tuple[str, ...] = ()
    kb_inputs: dict[str, tuple[str, ...]] = field(default_factory=dict)
    results: dict[str, tuple[ResultEnvelope, str]] = field(default_factory=dict)
    checkpoints: list[CheckpointRecord] = field(default_factory=list)
    model_calls: list[ModelCallRecord] = field(default_factory=list)

    def record_checkpoint(self, checkpoint: str, kind: str, **metadata: Any) -> None:
        self.checkpoints.append(CheckpointRecord(checkpoint=checkpoint, kind=kind, **metadata))

    def invoke_model(self, model: Any, messages: Any, *, purpose: str, attempt: int = 1) -> Any:
        """Count application invokes, not hidden SDK retries or graph visits."""
        self.record_checkpoint(purpose, "received")
        index = len(self.model_calls)
        record = ModelCallRecord(purpose=purpose, attempt=attempt)
        self.model_calls.append(record)
        try:
            response = model.invoke(messages)
        except Exception:
            self.model_calls[index] = record.model_copy(update={"outcome": "error"})
            raise
        usage = getattr(response, "usage_metadata", None)
        tokens = {}
        if isinstance(usage, dict):
            for key in ("input_tokens", "output_tokens", "total_tokens"):
                value = usage.get(key)
                if type(value) is int and value >= 0:
                    tokens[key] = value
        self.model_calls[index] = record.model_copy(update={"outcome": "returned", **tokens})
        return response

    def telemetry_snapshot(self) -> dict[str, Any]:
        token_totals = {
            key: sum(getattr(record, key) for record in self.model_calls)
            if all(getattr(record, key) is not None for record in self.model_calls) else None
            for key in ("input_tokens", "output_tokens", "total_tokens")
        }
        return {
            "run_id": self.run_id,
            "checkpoints": [record.model_dump() for record in self.checkpoints],
            "model_calls": [record.model_dump() for record in self.model_calls],
            "summary": {
                "application_model_calls": len(self.model_calls),
                "application_retries": sum(record.attempt > 1 for record in self.model_calls),
                "sdk_retry_count": None,
                "cost": None,
                "scope": "planner_and_analyst_generative_invokes",
                **token_totals,
            },
        }

    @staticmethod
    def _encode(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    def registry_snapshot(self) -> RegistrySnapshot:
        """Require the trusted registry before any mid-run registry access."""
        if self.registry is None:
            raise RuntimeRegistryError("trusted runtime registry is missing")
        return self.registry.snapshot(requester_run_id=self.run_id)

    def bind_execution_input(self, value: Any) -> None:
        """Snapshot caller task data at ingress; never derive it from worker prose."""
        from agents.executor_schema import ExecutionRequest
        from tools.registry import is_allowed

        self.registry_snapshot()
        if self.execution_input_json:
            raise RuntimeRegistryError("execution input is already bound")
        try:
            request = ExecutionRequest.model_validate(value)
            if not is_allowed(request.tool_name):
                raise ValueError("tool is not allowlisted")
        except (ValidationError, ValueError, TypeError) as exc:
            raise ContextBoundaryError("execution_input_schema_invalid") from exc
        self.execution_input_json = self._encode(request.model_dump())

    def confirmed_execution_request(self) -> dict[str, Any] | None:
        self.registry_snapshot()
        return json.loads(self.execution_input_json) if self.execution_input_json else None

    def accept_kb_documents(self, documents: list[dict]) -> None:
        self.registry_snapshot()
        self.kb_documents = tuple(self._encode(document) for document in documents)

    def record_kb_input(self, producer: str, documents: list[dict]) -> None:
        self.registry_snapshot()
        encoded = tuple(self._encode(document) for document in documents)
        if not encoded or encoded != self.kb_documents:
            raise RuntimeRegistryError("KB input differs from accepted retrieval")
        self.kb_inputs[producer] = encoded

    def kb_input_ids(self, producer: str) -> frozenset[str]:
        self.registry_snapshot()
        return frozenset(
            json.loads(document)["document_id"]
            for document in self.kb_inputs.get(producer, ())
        )

    def register_result(self, envelope: ResultEnvelope, payload: Any) -> None:
        self.registry_snapshot()
        self.results[envelope.result_id] = (envelope, self._encode(payload))

    def result_for(self, payload_key: str, payload: Any) -> ResultEnvelope | None:
        self.registry_snapshot()
        encoded = self._encode(payload)
        return next((
            envelope for envelope, accepted in reversed(tuple(self.results.values()))
            if envelope.payload_key == payload_key and accepted == encoded
        ), None)

    def close(self) -> None:
        self.original_query = ""
        self.execution_input_json = ""
        self.approval_callback = None
        self.kb_task = ""
        self.research_dispatched = False
        self.kb_documents = ()
        self.kb_inputs.clear()
        self.results.clear()
        self.checkpoints.clear()
        self.model_calls.clear()
        if self.registry is not None:
            self.registry.close()


def new_workflow_runtime() -> WorkflowRuntimeContext:
    run_id = str(uuid4())
    return WorkflowRuntimeContext(
        run_id=run_id,
        registry=RunSourceRegistry(run_id=run_id, _hmac_key=secrets.token_bytes(32)),
    )


@dataclass(frozen=True)
class ContextBoundaryResult:
    normalized_user_query: str
    records: tuple[ContextRecord, ...]
    message_count: int
    character_count: int
    discarded_metadata_fields: int


def normalize_public_context(
    user_query: Any,
    conversation_context: Any,
) -> ContextBoundaryResult:
    if not isinstance(user_query, str) or not user_query.strip():
        raise ContextBoundaryError("user_query must be a non-empty string")
    try:
        user_query.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise ContextBoundaryError("user_query contains invalid Unicode") from exc
    normalized_query = unicodedata.normalize("NFC", user_query)
    if len(normalized_query) > MAX_USER_QUERY_CHARS:
        raise ContextBoundaryError("user_query exceeds the limit")

    raw_messages = [] if conversation_context is None else conversation_context
    if not isinstance(raw_messages, list):
        raise ContextBoundaryError("conversation_context must be a list")
    if len(raw_messages) > MAX_CONTEXT_MESSAGES:
        raise ContextBoundaryError("conversation_context exceeds the message limit")

    records: list[ContextRecord] = []
    total_chars = 0
    discarded_fields = 0
    for raw_message in raw_messages:
        if not isinstance(raw_message, dict):
            raise ContextBoundaryError("each context message must be an object")
        discarded_fields += len(set(raw_message) - {"role", "content"})
        try:
            message = PublicContextMessage.model_validate(raw_message)
        except ValidationError as exc:
            raise ContextBoundaryError("context message does not match schema") from exc
        total_chars += len(message.content)
        if total_chars > MAX_CONTEXT_TOTAL_CHARS:
            raise ContextBoundaryError("conversation_context exceeds the total limit")
        records.append(ContextRecord(
            context_id=str(uuid4()),
            source_class="caller_context",
            origin_verified=False,
            content=message.content,
            declared_role=message.role,
        ))
    return ContextBoundaryResult(
        normalized_user_query=normalized_query,
        records=tuple(records),
        message_count=len(records),
        character_count=total_chars,
        discarded_metadata_fields=discarded_fields,
    )


class ScopeDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain_status: DomainStatus
    source_scope: SourceScope
    certainty: ScopeCertainty


_AMBIGUOUS_REFERENCE = re.compile(
    r"^(?:(?:hãy|please)\s+)?(?:so\s+sánh|phân\s+tích|tóm\s+tắt|compare|analy[sz]e|summari[sz]e)\s+"
    r"(?:(?:hai|các|những|the|two|these|those)\s+)*(?:phương\s+án|biện\s+pháp|kết\s+quả|options?|approaches?|results?)\s+"
    r"(?:vừa\s+nêu|nói\s+trên|ở\s+trên|previously\s+mentioned|above)[.!?]?$",
    re.IGNORECASE,
)
_KB_SOURCE = r"(?:knowledge\s*base|kb|tài\s+liệu\s+hệ\s+thống|system\s+documents?)"
_CALLER_DATA = (
    r"(?:dữ\s+liệu\s+(?:caller|hội\s+thoại(?:\s+do\s+caller\s+cung\s+cấp)?|"
    r"được\s+cung\s+cấp|tôi\s+cung\s+cấp)|caller\s+(?:data|context)|"
    r"context\s+(?:tôi\s+gửi|do\s+caller\s+gửi))(?:\s+được\s+cung\s+cấp)?"
)
_CALLER_SOURCE = (
    r"(?:" + _CALLER_DATA + r"|context(?:\s+(?:được\s+cung\s+cấp|caller))?|conversation\s+context)"
)
_USE_SOURCE = r"(?:use|using|from|with|based\s+on|dùng|sử\s+dụng|dựa\s+(?:trên|vào)|bằng)"
_PAIRED_SOURCES = (
    r"\b(?:" + _KB_SOURCE + r"\s+(?:and|và)\s+" + _CALLER_SOURCE
    + r"|" + _CALLER_SOURCE + r"\s+(?:and|và)\s+" + _KB_SOURCE + r")\b"
)
_BOTH_SOURCE_CLAUSE = _USE_SOURCE + r"\s+(?:(?:both|cả)\s+)?" + _PAIRED_SOURCES
_BOTH_SOURCE_SUFFIX = re.compile(
    r"(?P<task>.+?)(?:,\s*(?:hãy\s+)?kết\s+luận)?\s+" + _BOTH_SOURCE_CLAUSE
    + r"(?:,?\s*(?:đồng\s+thời\s+)?(?:hãy\s+)?phân\s+biệt\s+rõ\s+hai\s+nguồn)?[.!]?",
    re.IGNORECASE,
)
_BOTH_SOURCE_PREFIX = re.compile(
    r"(?:(?:please|hãy)\s+)?" + _BOTH_SOURCE_CLAUSE + r"\s*[,;:]\s*(?P<task>.+)", re.IGNORECASE,
)
_CALLER_REQUEST = re.compile(
    r"\b(?:use|using|based\s+on|dùng|sử\s+dụng|dựa\s+(?:trên|vào)|bằng)\s+"
    r"(?:the\s+)?" + _CALLER_SOURCE + r"\b|"
    r"\b(?:dựa\s+(?:trên|vào)|based\s+on|rely\s+on)\s+caller\b|"
    r"^(?:(?:hãy|please)\s+)?(?:trích|tóm\s+tắt|phân\s+tích|so\s+sánh|quote|summari[sz]e|analy[sz]e|compare)\s+"
    r"(?:the\s+)?" + _CALLER_DATA + r"\b", re.IGNORECASE,
)
_KB_REFERENCE = re.compile(r"\b" + _KB_SOURCE + r"\b", re.IGNORECASE)
_DENIAL_VERB = r"\b(?:không|đừng|do\s+not|don't)\s+(?:dùng|sử\s+dụng|use|using)\s+(?:the\s+)?"
_CALLER_DENIAL = re.compile(_DENIAL_VERB + _CALLER_SOURCE + r"\b", re.IGNORECASE)
_KB_DENIAL = re.compile(_DENIAL_VERB + _KB_SOURCE + r"\b", re.IGNORECASE)
_KNOWN_OUT_OF_SCOPE = re.compile(
    r"\b(?:bitcoin|khách\s+sạn|hotel|nấu\s+phở|công\s+thức\s+nấu|weather|"
    r"thời\s+tiết)\b",
    re.IGNORECASE,
)
_QUOTED_SCOPE_TEXT = re.compile(r'"[^"\n]*"|‘[^’\n]*’|“[^”\n]*”|(?<!\w)\x27[^\x27\n]*\x27(?!\w)')
_EXPLICIT_AI_SECURITY_TOPIC = re.compile(
    r"\b(?:prompt\s+injection|coordinator\s+flaw|conversation\s+context\s+spoofing|(?:bảo\s+mật|an\s+toàn|security)"
    r"\s+(?:AI|LLM)|(?:AI|LLM|agent)\s+security)\b",
    re.IGNORECASE,
)
_SECURITY_TASK_PREFIX = re.compile(
    r"^(?:(?:please|hãy)\s+)?(?:explain|describe|analy[sz]e|compare|discuss|research|"
    r"giải\s+thích|phân\s+tích|so\s+sánh|nghiên\s+cứu|đề\s+xuất)\b", re.IGNORECASE,
)
_NON_SECURITY_REQUEST = re.compile(
    r"\b(?:weather\s+(?:forecast|today|tomorrow)|(?:what|tell).{0,20}weather|"
    r"(?:dự\s+báo|xem)\s+thời\s+tiết|(?:giá|price\s+of)\s+bitcoin)\b", re.IGNORECASE,
)


def _scope_text(query: str) -> str:
    # Preserve positions for projection, but never read selectors from quotes.
    return _QUOTED_SCOPE_TEXT.sub(lambda match: " " * len(match.group()), query)


def _source_selection(query: str) -> tuple[SourceScope, str | None]:
    """Shared bounded grammar for source policy and KB-task projection."""
    policy = _scope_text(query)
    caller_denied = bool(_CALLER_DENIAL.search(policy))
    kb_denied = bool(_KB_DENIAL.search(policy))
    positive = _KB_DENIAL.sub(" ", _CALLER_DENIAL.sub(" ", policy))
    paired = bool(re.search(_PAIRED_SOURCES, positive, re.IGNORECASE))
    caller_requested = paired or bool(_CALLER_REQUEST.search(positive))
    kb_requested = bool(_KB_REFERENCE.search(positive))
    if (caller_requested and caller_denied) or (kb_requested and kb_denied):
        return "ambiguous", None
    if caller_requested and kb_requested:
        match = _BOTH_SOURCE_SUFFIX.fullmatch(policy) or _BOTH_SOURCE_PREFIX.fullmatch(policy)
        if match is None:
            return "both", None
        task = query[match.start("task"):match.end("task")].strip(" ,;.!?")
        task_policy = _scope_text(task)
        if (
            not task or _CALLER_REQUEST.search(task_policy)
            or re.search(_PAIRED_SOURCES, task_policy, re.IGNORECASE)
            or _AMBIGUOUS_REFERENCE.fullmatch(task_policy)
        ):
            return "both", None
        return "both", task + "."
    if caller_requested:
        return "caller_only", None
    if kb_denied:
        return "ambiguous", None
    return "kb_only", query


def project_kb_task(user_query: str, source_scope: SourceScope) -> str | None:
    query = " ".join(unicodedata.normalize("NFC", user_query).split())
    selected_scope, task = _source_selection(query)
    return task if selected_scope == source_scope else None


def classify_scope_query(user_query: str) -> ScopeDecision:
    """Read source-use grammar and task intent only from the original query."""
    if not isinstance(user_query, str) or not user_query.strip():
        raise ValueError("user_query must be a non-empty string")
    query = " ".join(unicodedata.normalize("NFC", user_query).split())
    scope_query = _scope_text(query)
    source_scope, kb_task = _source_selection(query)
    domain_query = _scope_text(kb_task) if kb_task is not None else scope_query
    security_task = (
        bool(_SECURITY_TASK_PREFIX.search(domain_query))
        and bool(_EXPLICIT_AI_SECURITY_TOPIC.search(domain_query))
        and not _NON_SECURITY_REQUEST.search(domain_query)
    )
    if _KNOWN_OUT_OF_SCOPE.search(scope_query) and not security_task:
        return ScopeDecision(
            domain_status="unsupported",
            source_scope="ambiguous",
            certainty="clear",
        )
    if _AMBIGUOUS_REFERENCE.fullmatch(scope_query):
        return ScopeDecision(
            domain_status="uncertain",
            source_scope="ambiguous",
            certainty="uncertain",
        )

    if source_scope == "ambiguous" or (source_scope == "both" and kb_task is None):
        return ScopeDecision(domain_status="uncertain", source_scope=source_scope, certainty="uncertain")
    # Caller-only finishes before the legacy route/domain classifier. Require
    # an explicit supported topic here; context cannot supply that topic.
    if source_scope == "caller_only" and not _EXPLICIT_AI_SECURITY_TOPIC.search(scope_query):
        return ScopeDecision(
            domain_status="uncertain",
            source_scope=source_scope,
            certainty="uncertain",
        )
    return ScopeDecision(
        domain_status="supported",
        source_scope=source_scope,
        certainty="clear",
    )


def context_boundary_node(
    state: dict[str, Any],
    runtime: Runtime[WorkflowRuntimeContext],
) -> dict[str, Any]:
    """Validate caller input, initialize trusted registry, and erase raw context."""
    context = runtime.context
    try:
        if context is None or context.registry is None:
            raise RuntimeRegistryError("trusted runtime context or registry is missing")
        if context.registry.run_id != context.run_id:
            raise RuntimeRegistryError("runtime context and registry run IDs differ")
        boundary = normalize_public_context(
            state.get("user_query"),
            state.get("conversation_context"),
        )
        snapshot = context.registry.initialize(
            boundary.records,
            discarded_metadata_fields=boundary.discarded_metadata_fields,
        )
        context.original_query = boundary.normalized_user_query
        if state.get("execution_input") is not None:
            context.bind_execution_input(state["execution_input"])
        context.record_checkpoint(
            "context_boundary", "received",
            received_context_ids=tuple(record.context_id for record in boundary.records),
        )
        return {
            "user_query": boundary.normalized_user_query,
            "conversation_context": [],
            "execution_input": None,
            "has_context": bool(boundary.records),
            "context_message_count": boundary.message_count,
            "context_character_count": boundary.character_count,
            "context_digest": snapshot.digest,
            "context_metadata_discarded": boundary.discarded_metadata_fields,
            "allowed_use": "none",
        }
    except ContextBoundaryError as exc:
        reason_code = "execution_input_schema_invalid" if str(exc) == "execution_input_schema_invalid" else "context_schema_invalid"
    except RuntimeRegistryError:
        reason_code = "runtime_registry_unavailable"
    return {
        "conversation_context": [],
        "execution_input": None,
        "has_context": False,
        "context_message_count": 0,
        "context_character_count": 0,
        "allowed_use": "none",
        "context_boundary_error": reason_code,
    }
