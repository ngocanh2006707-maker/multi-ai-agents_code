"""Schema đầu ra có cấu trúc của Analyst Agent."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator


ShortText = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=500),
]
LongText = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=4000),
]
EvidenceId = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=200),
]


class StrictAnalysisModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RetrievedDocument(BaseModel):
    """Phần metadata Analyst được phép nhận từ Research Agent."""

    model_config = ConfigDict(extra="ignore", allow_inf_nan=False)

    document_id: EvidenceId
    chunk_id: EvidenceId
    content: Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=1, max_length=12000),
    ]
    title: ShortText | None = None
    source: EvidenceId
    trust_level: float = Field(ge=0.0, le=1.0)
    similarity_score: float = Field(ge=0.0, le=1.0)


class ConversationMessage(StrictAnalysisModel):
    """Message hội thoại được coi là dữ liệu không tin cậy."""

    role: Literal["user", "assistant"]
    content: LongText


class DefenseComparison(StrictAnalysisModel):
    """Phân tích một biện pháp phòng thủ."""

    defense: ShortText = Field(
        description="Tên biện pháp phòng thủ được phân tích."
    )
    purpose: LongText = Field(
        description="Mục đích chính của biện pháp."
    )
    strengths: list[ShortText] = Field(
        default_factory=list,
        max_length=20,
        description="Các ưu điểm chính."
    )
    weaknesses: list[ShortText] = Field(
        default_factory=list,
        max_length=20,
        description="Các hạn chế hoặc nhược điểm."
    )
    suitable_for: list[ShortText] = Field(
        default_factory=list,
        max_length=20,
        description="Các trường hợp sử dụng phù hợp."
    )
    evidence_document_ids: list[EvidenceId] = Field(
        min_length=1,
        max_length=20,
        description="Document ID làm bằng chứng cho phân tích biện pháp này.",
    )


class Contradiction(StrictAnalysisModel):
    """Hai phát biểu mâu thuẫn và các document nguồn tương ứng."""

    claim_a: LongText
    claim_b: LongText
    document_ids: list[EvidenceId] = Field(min_length=2, max_length=20)
    explanation: LongText

    @model_validator(mode="after")
    def require_distinct_documents(self):
        if len(set(self.document_ids)) < 2:
            raise ValueError("Mâu thuẫn phải tham chiếu ít nhất hai document khác nhau")
        return self


class AnalysisDraft(StrictAnalysisModel):
    """Output có cấu trúc do LLM sinh; confidence được hệ thống thêm sau."""

    topic: ShortText = Field(
        description="Chủ đề đang được phân tích."
    )
    summary: LongText = Field(
        description="Tóm tắt kết quả phân tích."
    )
    comparison: list[DefenseComparison] = Field(
        default_factory=list,
        max_length=20,
        description="Kết quả phân tích hoặc so sánh từng biện pháp."
    )
    contradictions: list[Contradiction] = Field(
        default_factory=list,
        max_length=20,
        description="Mâu thuẫn được phát hiện giữa các nguồn."
    )
    recommendation: LongText = Field(
        description="Khuyến nghị dựa trên tài liệu được cung cấp."
    )
    evidence_document_ids: list[EvidenceId] = Field(
        default_factory=list,
        max_length=50,
        description="Các document ID hỗ trợ summary và recommendation.",
    )


class AnalysisResult(AnalysisDraft):
    """Kết quả cuối sau khi hệ thống tự tính confidence."""

    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Độ chắc chắn của kết luận, từ 0 đến 1."
    )


def analysis_wire_schema() -> dict:
    """Schema phẳng tương thích Gemini, tách khỏi strict runtime schema.

    Không truyền trực tiếp JSON Schema do Pydantic sinh vì schema đó có nhiều
    constraint và ``$defs/$ref`` lồng nhau, có thể vượt mức complexity Gemini
    chấp nhận. Kết quả API vẫn được validate lại bằng ``AnalysisDraft``.
    """
    string_list = {"type": "array", "items": {"type": "string"}}
    comparison_item = {
        "type": "object",
        "properties": {
            "defense": {"type": "string"},
            "purpose": {"type": "string"},
            "strengths": string_list,
            "weaknesses": string_list,
            "suitable_for": string_list,
            "evidence_document_ids": string_list,
        },
        "required": ["defense", "purpose", "evidence_document_ids"],
    }
    contradiction_item = {
        "type": "object",
        "properties": {
            "claim_a": {"type": "string"},
            "claim_b": {"type": "string"},
            "document_ids": string_list,
            "explanation": {"type": "string"},
        },
        "required": ["claim_a", "claim_b", "document_ids", "explanation"],
    }
    return {
        "title": "AnalysisDraft",
        "description": "Phân tích dựa trên bằng chứng được cung cấp.",
        "type": "object",
        "properties": {
            "topic": {"type": "string"},
            "summary": {"type": "string"},
            "comparison": {
                "type": "array",
                "items": comparison_item,
            },
            "contradictions": {
                "type": "array",
                "items": contradiction_item,
            },
            "recommendation": {"type": "string"},
            "evidence_document_ids": string_list,
        },
        "required": [
            "topic",
            "summary",
            "comparison",
            "contradictions",
            "recommendation",
            "evidence_document_ids",
        ],
    }
