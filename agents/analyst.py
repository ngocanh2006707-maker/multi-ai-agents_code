"""
Analyst Agent — phân tích, tổng hợp, so sánh dựa trên retrieved_documents.

Input: user_query, retrieved_documents (từ state).
Output (ghi vào state.analysis_result): dict theo schema mục 5 của spec
(topic, summary, comparison[], recommendation, confidence).

Trách nhiệm:
- So sánh, tìm điểm giống/khác, ưu/nhược điểm, use case.
- Phát hiện mâu thuẫn giữa các nguồn (so sánh nội dung theo document_id
  khác nhau nói về cùng 1 chủ đề).
- Tự đánh giá confidence dựa trên số lượng & trust_level của nguồn.

KHÔNG được:
- Gọi tool hệ thống trực tiếp.

Sẽ triển khai ở Phase 5.
"""

from __future__ import annotations

import math
import re

from pydantic import ValidationError

from agents.analyst_schema import (
    AnalysisDraft,
    AnalysisResult,
    RetrievedDocument,
    analysis_wire_schema,
)
from agents.llm import get_llm
from agents.prompts.analyst import (
    ANALYST_SYSTEM_PROMPT,
    ANALYST_SYSTEM_PROMPT_OFF,
    build_analyst_input,
)
from graph.state import AgentState
from security.config import load_security_settings
from security.coordination_guard import KB_SCOPE_TEMPLATE, safe_error
from security.context_guard import WorkflowRuntimeContext
from security.prompt_canary import canary_instruction


MAX_ANALYST_DOCUMENTS = 12
MAX_ANALYST_CONTEXT_CHARS = 30000
MAX_USER_QUERY_CHARS = 4000

_COMPARISON_QUERY = re.compile(
    r"\b(?:so\s+sánh|compare|comparison|versus|vs\.?)\b",
    re.I,
)


class AnalysisQualityError(ValueError):
    """Output có cấu trúc đúng kiểu nhưng không đủ chất lượng/bằng chứng."""


def _validate_inputs(state: AgentState) -> tuple[str, list[dict]]:
    """Kiểm tra và giới hạn context trước khi bất kỳ dữ liệu nào đi tới LLM."""
    raw_conversation = state.get("conversation_context")
    if raw_conversation is not None and (
        not isinstance(raw_conversation, list) or raw_conversation
    ):
        raise ValueError("Analyst is KB-only; caller context is not supported")
    user_query = state.get("user_query")
    if not isinstance(user_query, str) or not user_query.strip():
        raise ValueError("user_query phải là chuỗi không rỗng")
    user_query = user_query.strip()
    if len(user_query) > MAX_USER_QUERY_CHARS:
        raise ValueError(
            f"user_query vượt giới hạn {MAX_USER_QUERY_CHARS} ký tự"
        )

    raw_documents = state.get("retrieved_documents") or []
    if not isinstance(raw_documents, list):
        raise TypeError("retrieved_documents phải là list")
    if len(raw_documents) > MAX_ANALYST_DOCUMENTS:
        raise ValueError(
            f"retrieved_documents vượt giới hạn {MAX_ANALYST_DOCUMENTS} items"
        )
    documents = [
        RetrievedDocument.model_validate(document).model_dump()
        for document in raw_documents
    ]

    total_chars = sum(len(document["content"]) for document in documents)
    if total_chars > MAX_ANALYST_CONTEXT_CHARS:
        raise ValueError(
            f"Analyst context vượt giới hạn {MAX_ANALYST_CONTEXT_CHARS} ký tự"
        )
    return user_query, documents


def _validate_draft_quality(
    draft: AnalysisDraft,
    user_query: str,
    documents: list[dict],
) -> None:
    """Bảo đảm output bám nguồn và đáp ứng intent so sánh."""
    valid_evidence_ids = {
        str(document["document_id"]) for document in documents
    }

    cited_ids = set(draft.evidence_document_ids)
    for comparison in draft.comparison:
        cited_ids.update(comparison.evidence_document_ids)
    for contradiction in draft.contradictions:
        cited_ids.update(contradiction.document_ids)

    if valid_evidence_ids and not draft.evidence_document_ids:
        raise AnalysisQualityError(
            "summary/recommendation phải có evidence_document_ids"
        )
    unknown_ids = cited_ids - valid_evidence_ids
    if unknown_ids:
        raise AnalysisQualityError(
            f"Output trích dẫn evidence ID không tồn tại: {sorted(unknown_ids)}"
        )

    if _COMPARISON_QUERY.search(user_query):
        defenses = {
            comparison.defense.casefold() for comparison in draft.comparison
        }
        if len(defenses) < 2:
            raise AnalysisQualityError(
                "Câu hỏi so sánh cần ít nhất hai DefenseComparison khác nhau"
            )


def _invoke_analysis_draft(
    messages: list[tuple[str, str]],
    user_query: str,
    documents: list[dict],
    *,
    runtime_context: WorkflowRuntimeContext | None = None,
    unprotected: bool = False,
) -> AnalysisDraft:
    """Thử lại một lần cho lỗi tạm thời hoặc output có cấu trúc chưa hợp lệ."""
    if unprotected:
        from graph.baseline import decode_json
        from agents.planner import _invoke_model, _response_text
        response = _invoke_model(get_llm(), messages, purpose="analyst", runtime_context=runtime_context)
        raw = _response_text(response)
        try:
            return decode_json(raw)
        except ValueError:
            return {"summary": raw}
    structured_llm = get_llm().with_structured_output(analysis_wire_schema())
    last_error: Exception | None = None
    retryable = (
        ValidationError,
        TimeoutError,
        ConnectionError,
        AnalysisQualityError,
    )
    for attempt in range(2):
        try:
            result = (
                runtime_context.invoke_model(structured_llm, messages, purpose="analyst", attempt=attempt + 1)
                if runtime_context is not None else structured_llm.invoke(messages)
            )
            draft = (
                result
                if isinstance(result, AnalysisDraft)
                else AnalysisDraft.model_validate(result)
            )
            _validate_draft_quality(
                draft,
                user_query,
                documents,
            )
            return draft
        except Exception as exc:
            last_error = exc
            if attempt == 1 or not isinstance(exc, retryable):
                break
    raise RuntimeError("analysis_generation_failed") from last_error


def _calculate_confidence(
    documents: list[dict],
    *,
    contradiction_count: int = 0,
) -> float:
    """Tính confidence từ provenance, trust, relevance và mức độ nhất quán."""
    if not documents:
        return 0.0

    quality_by_source: dict[str, list[float]] = {}
    for document in documents:
        source = str(document.get("source", "")).strip()
        document_id = str(document.get("document_id", "")).strip()
        source_id = source or document_id
        if not source_id:
            continue

        try:
            trust_level = float(document.get("trust_level", 0.0))
        except (TypeError, ValueError):
            trust_level = 0.0
        if not math.isfinite(trust_level):
            trust_level = 0.0
        trust_level = max(0.0, min(1.0, trust_level))

        try:
            similarity = float(document.get("similarity_score", 0.0))
        except (TypeError, ValueError):
            similarity = 0.0
        if not math.isfinite(similarity):
            similarity = 0.0
        similarity = max(0.0, min(1.0, similarity))

        quality_by_source.setdefault(source_id, []).append(
            trust_level * similarity
        )

    if not quality_by_source:
        return 0.0

    source_quality = [
        sum(values) / len(values) for values in quality_by_source.values()
    ]
    average_quality = sum(source_quality) / len(source_quality)
    source_coverage = min(len(source_quality) / 3.0, 1.0)
    confidence = (0.8 * average_quality) + (0.2 * source_coverage)
    confidence *= max(0.5, 1.0 - (0.1 * max(0, contradiction_count)))
    return round(max(0.0, min(1.0, confidence)), 2)


def _empty_analysis(message: str) -> dict:
    """Tạo kết quả đúng schema khi không thể thực hiện phân tích."""
    return AnalysisResult(
        topic="Không đủ dữ liệu",
        summary=message,
        comparison=[],
        contradictions=[],
        recommendation=(
            "Cần bổ sung tài liệu liên quan từ Knowledge Base "
            "trước khi đưa ra kết luận."
        ),
        confidence=0.0,
    ).model_dump()


def analyst_node(state: AgentState, *, runtime_context: WorkflowRuntimeContext | None = None) -> AgentState:
    """Protected KB analysis in ON; raw caller/KB analysis in OFF."""
    if not load_security_settings().defense_enabled:
        from graph.baseline import analyst_node as baseline_analyst
        return baseline_analyst(state, runtime_context=runtime_context)
    try:
        user_query, documents = _validate_inputs(state)
        if not documents:
            return {
                **state,
                "analysis_result": _empty_analysis(
                    "Research Agent chưa cung cấp tài liệu để phân tích."
                ),
                "current_agent": "analyst",
            }
        settings = load_security_settings()
        analyst_system_prompt = (
            ANALYST_SYSTEM_PROMPT
            if settings.harden_untrusted_context
            else ANALYST_SYSTEM_PROMPT_OFF
        ) + canary_instruction(state.get("canary_id"))
        if state.get("kb_task"):
            analyst_system_prompt += "\n" + KB_SCOPE_TEMPLATE
        messages = [
            ("system", analyst_system_prompt),
            (
                "human",
                build_analyst_input(
                    user_query,
                    documents,
                    harden_untrusted_context=(
                        settings.harden_untrusted_context
                    ),
                ),
            ),
        ]
        draft = _invoke_analysis_draft(
            messages,
            user_query,
            documents,
            runtime_context=runtime_context,
        )
        analysis = AnalysisResult(
            **draft.model_dump(),
            confidence=_calculate_confidence(
                documents,
                contradiction_count=len(draft.contradictions),
            ),
        )

        return {
            **state,
            "analysis_result": analysis.model_dump(),
            "current_agent": "analyst",
        }
    except Exception as exc:
        if state.get("kb_task") and isinstance(exc.__cause__, (ValidationError, AnalysisQualityError)):
            # The public KB channel exhausted its existing two-attempt budget.
            # Planner rejects this candidate and retains independent parts.
            return {**state, "analysis_result": {}, "current_agent": "analyst"}
        errors = list(state.get("errors", []))
        errors.append(safe_error("analyst", "analysis_error", exc))
        return {
            **state,
            "analysis_result": _empty_analysis(
                "Analyst Agent không thể hoàn thành phân tích."
            ),
            "current_agent": "analyst",
            "errors": errors,
        }
