"""Schema input/output và tham số tool của Executor Agent."""

import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


ExecutionStatus = Literal["success", "error", "denied"]
MAX_EXECUTION_PARAMS_BYTES = 1_000_000


class ToolParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DatasetPathParams(ToolParams):
    path: str = Field(min_length=1, max_length=500)

    @field_validator("path")
    @classmethod
    def require_relative_path(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or Path(normalized).is_absolute():
            raise ValueError("path phải là đường dẫn tương đối")
        if ".." in Path(normalized).parts:
            raise ValueError("path không được chứa '..'")
        return normalized


class CalculateMetricsParams(ToolParams):
    metric: str = Field(min_length=1, max_length=100)
    records: list[dict[str, Any]] = Field(min_length=1, max_length=10_000)
    k: int | None = Field(default=None, ge=1, le=10_000)


class CalculateMetricsFromDatasetParams(DatasetPathParams):
    metric: str = Field(min_length=1, max_length=100)
    k: int | None = Field(default=None, ge=1, le=10_000)


class RunSecurityTestParams(ToolParams):
    config: dict[str, Any]


class SaveTestResultParams(ToolParams):
    result: dict[str, Any]
    path: str = Field(min_length=1, max_length=500)

    @field_validator("path")
    @classmethod
    def require_relative_json_path(cls, value: str) -> str:
        normalized = value.strip()
        if (
            not normalized
            or Path(normalized).is_absolute()
            or ".." in Path(normalized).parts
        ):
            raise ValueError("path phải nằm tương đối trong data/results/")
        if Path(normalized).suffix.lower() != ".json":
            raise ValueError("save_test_result chỉ chấp nhận file .json")
        return normalized


_TOOL_PARAM_SCHEMAS: dict[str, type[ToolParams]] = {
    "read_dataset": DatasetPathParams,
    "calculate_metrics": CalculateMetricsParams,
    "calculate_metrics_from_dataset": CalculateMetricsFromDatasetParams,
    "run_security_test": RunSecurityTestParams,
    "save_test_result": SaveTestResultParams,
}


class ExecutionRequest(BaseModel):
    """Yêu cầu thực thi do Planner tạo và chuyển cho Executor."""

    model_config = ConfigDict(extra="forbid")

    tool_name: str = Field(
        min_length=1,
        description="Tên tool Executor được yêu cầu gọi.",
    )
    params: dict[str, Any] = Field(
        default_factory=dict,
        description="Các tham số được truyền cho tool.",
    )

    @model_validator(mode="after")
    def normalize_tool_name(self) -> "ExecutionRequest":
        self.tool_name = self.tool_name.strip()
        if not self.tool_name:
            raise ValueError("tool_name không được rỗng")
        params_schema = _TOOL_PARAM_SCHEMAS.get(self.tool_name)
        if params_schema is not None:
            self.params = params_schema.model_validate(self.params).model_dump()
        try:
            encoded = json.dumps(
                self.params,
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("params phải là JSON hợp lệ") from exc
        if len(encoded) > MAX_EXECUTION_PARAMS_BYTES:
            raise ValueError(
                f"params vượt giới hạn {MAX_EXECUTION_PARAMS_BYTES} bytes"
            )
        return self


class ExecutionResult(BaseModel):
    """Kết quả có cấu trúc do Executor ghi vào shared state."""

    model_config = ConfigDict(extra="forbid")

    status: ExecutionStatus = Field(
        description="Trạng thái thực thi: success, error hoặc denied.",
    )
    tool: str = Field(
        min_length=1,
        description="Tên tool được yêu cầu.",
    )
    result: Any = Field(
        default=None,
        description="Dữ liệu có cấu trúc do tool trả về.",
    )
    error: str | None = Field(
        default=None,
        description="Thông báo lỗi khi thực thi thất bại hoặc bị từ chối.",
    )

    @model_validator(mode="after")
    def validate_status_fields(self) -> "ExecutionResult":
        self.tool = self.tool.strip()
        if not self.tool:
            raise ValueError("ExecutionResult.tool không được rỗng")
        if self.status == "success" and self.error is not None:
            raise ValueError("ExecutionResult thành công không được chứa error")
        if self.status == "success" and self.result is None:
            raise ValueError("ExecutionResult thành công phải có result")
        if self.status in {"error", "denied"} and not self.error:
            raise ValueError(
                f"ExecutionResult status={self.status!r} phải có error"
            )
        if self.status in {"error", "denied"} and self.result is not None:
            raise ValueError(
                f"ExecutionResult status={self.status!r} không được chứa result"
            )
        if self.error is not None:
            self.error = self.error.strip()
            if len(self.error) > 1000:
                raise ValueError("ExecutionResult.error vượt giới hạn 1000 ký tự")
        return self
