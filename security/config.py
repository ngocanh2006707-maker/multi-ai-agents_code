"""
Cấu hình chế độ phòng thủ (mục 13 của spec).

Đọc DEFENSE_MODE từ env (off | on) hoặc configs/defense_off.yaml /
configs/defense_on.yaml. Toàn hệ thống PHẢI chạy được ở cả 2 chế độ
ngay từ baseline. Khi defense_off, detector vẫn chạy để tạo telemetry nhưng
policy chỉ pass-through; khi defense_on, guard mới block/filter/redact.

Sẽ triển khai ở Phase 9.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, Field


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class SecuritySettings(BaseModel):
    defense_enabled: bool = False
    input_guard: bool = False
    retrieval_guard: bool = False
    output_guard: bool = False
    min_trust_level: float = Field(default=0.5, ge=0.0, le=1.0)
    verify_content_hash: bool = True
    require_managed_trust: bool = True
    require_allowlisted_source: bool = True
    trust_aware_ranking: bool = True
    harden_untrusted_context: bool = True
    enforce_confidence_gate: bool = True


def load_security_settings(mode: str | None = None) -> SecuritySettings:
    """Đọc defense_off/on YAML; argument hoặc env quyết định mode cuối cùng."""
    selected_mode = (mode or os.environ.get("DEFENSE_MODE", "off")).strip().lower()
    if selected_mode not in {"off", "on"}:
        raise ValueError("DEFENSE_MODE phải là 'off' hoặc 'on'")

    path = PROJECT_ROOT / "configs" / f"defense_{selected_mode}.yaml"
    with path.open("r", encoding="utf-8") as file:
        raw = yaml.safe_load(file) or {}

    security = dict(raw.get("security", {}))
    security["defense_enabled"] = selected_mode == "on"
    return SecuritySettings.model_validate(security)


def is_defense_enabled() -> bool:
    return load_security_settings().defense_enabled
