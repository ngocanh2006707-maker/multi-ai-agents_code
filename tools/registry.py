"""
Allowlist Tool Policy cho Executor Agent (mục 6 của spec).

Tool được phép ban đầu:
    read_dataset, calculate_metrics, calculate_metrics_from_dataset,
    run_security_test, save_test_result

KHÔNG bao giờ thêm vào registry (trừ khi có quyết định thiết kế tường
minh, tách riêng, có review):
    shell, delete_file, read_secret, send_network_request

is_allowed(tool_name) -> bool
get_tool(tool_name) -> callable

Sẽ triển khai ở Phase 6.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType
from typing import Any

import yaml


ToolCallable = Callable[..., Any]


class ToolNotAllowedError(PermissionError):
    """Được phát sinh khi Executor yêu cầu tool ngoài allowlist."""


class RegistryFrozenError(RuntimeError):
    """Registry không được thay đổi sau giai đoạn bootstrap."""


_PROHIBITED_TOOLS = frozenset({
    "shell",
    "delete_file",
    "read_secret",
    "send_network_request",
})


def _load_configured_allowlist() -> frozenset[str]:
    path = Path(__file__).resolve().parents[1] / "configs" / "config.yaml"
    with path.open("r", encoding="utf-8") as file:
        raw = yaml.safe_load(file) or {}
    names = (raw.get("executor") or {}).get("allowlist") or []
    if not isinstance(names, list) or not all(isinstance(name, str) for name in names):
        raise ValueError("executor.allowlist trong config phải là list[str]")
    normalized = frozenset(name.strip() for name in names if name.strip())
    prohibited = normalized & _PROHIBITED_TOOLS
    if prohibited:
        raise ValueError(f"Config chứa tool bị cấm: {sorted(prohibited)}")
    return normalized


_CONFIGURED_ALLOWLIST = _load_configured_allowlist()


# Không tự động tìm hoặc import callable dựa trên input của người dùng.
# Tool chỉ được phép sau khi được đăng ký tường minh trong mã nguồn.
_registry_data: dict[str, ToolCallable] = {}
_registry_frozen = False


def register_tool(name: str, tool: ToolCallable) -> None:
    """Đăng ký tường minh một callable vào allowlist."""
    normalized_name = name.strip()
    if not normalized_name:
        raise ValueError("Tên tool không được rỗng")
    if not callable(tool):
        raise TypeError("Tool phải là callable")
    if normalized_name in _PROHIBITED_TOOLS:
        raise ToolNotAllowedError(f"Tool bị cấm tuyệt đối: {normalized_name!r}")
    if normalized_name not in _CONFIGURED_ALLOWLIST:
        raise ToolNotAllowedError(
            f"Tool không có trong executor.allowlist: {normalized_name!r}"
        )
    if _registry_frozen:
        raise RegistryFrozenError("Tool registry đã được khóa")
    if normalized_name in _registry_data:
        raise ValueError(f"Tool đã được đăng ký: {normalized_name!r}")
    _registry_data[normalized_name] = tool


def is_allowed(tool_name: str) -> bool:
    """Kiểm tra tool có nằm trong registry allowlist hay không."""
    return tool_name.strip() in _registry_data


def get_tool(tool_name: str) -> ToolCallable:
    """Lấy callable sau khi kiểm tra allowlist."""
    normalized_name = tool_name.strip()
    if normalized_name not in _registry_data:
        raise ToolNotAllowedError(
            f"Tool không nằm trong allowlist: {normalized_name!r}"
        )
    return _registry_data[normalized_name]


def list_allowed_tools() -> tuple[str, ...]:
    """Trả danh sách tool được phép theo thứ tự ổn định."""
    return tuple(sorted(_registry_data))


# Chỉ đăng ký tool đã có phần triển khai và đã được xem xét.
from tools.dataset_tools import read_dataset
from tools.metric_tools import (
    calculate_metrics,
    calculate_metrics_from_dataset,
    run_security_test,
)
from tools.result_tools import save_test_result

register_tool("read_dataset", read_dataset)
register_tool("calculate_metrics", calculate_metrics)
register_tool("calculate_metrics_from_dataset", calculate_metrics_from_dataset)
register_tool("run_security_test", run_security_test)
register_tool("save_test_result", save_test_result)

missing_implementations = _CONFIGURED_ALLOWLIST - set(_registry_data)
if missing_implementations:
    raise RuntimeError(
        f"Tool được allow trong config nhưng chưa có implementation: "
        f"{sorted(missing_implementations)}"
    )

_registry_frozen = True
_TOOL_REGISTRY = MappingProxyType(_registry_data)
