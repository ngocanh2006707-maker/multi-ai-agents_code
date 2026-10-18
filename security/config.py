"""
Cấu hình chế độ phòng thủ (mục 13 của spec).

Đọc DEFENSE_MODE từ env (off | on) hoặc configs/defense_off.yaml /
configs/defense_on.yaml. Toàn hệ thống PHẢI chạy được ở cả 2 chế độ
ngay từ baseline. Public OFF chạy graph không bảo vệ, bỏ mọi defense checkpoint.
Public ON giữ workflow/guard đã kiểm chứng. Gọi guard trực tiếp vẫn có thể dùng
observe-only mode cho unit measurement; đó không phải public OFF workflow.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


PROJECT_ROOT = Path(__file__).resolve().parents[1]

_DEFAULT_PROMPT_RISK_WEIGHTS = {
    "override": 0.65,
    "internal_target": 0.70,
    "sensitive_action": 0.70,
    "roleplay": 0.15,
    "authority_claim": 0.55,
    "obfuscation": 0.20,
    "tool_intent": 0.45,
}


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
    prompt_risk_weights: dict[str, float] = Field(
        default_factory=lambda: dict(_DEFAULT_PROMPT_RISK_WEIGHTS)
    )
    prompt_risk_medium_threshold: float = Field(default=0.55, ge=0.0, le=1.0)
    prompt_risk_high_threshold: float = Field(default=0.80, ge=0.0, le=1.0)
    retrieval_risk_medium_threshold: float = Field(default=0.55, ge=0.0, le=1.0)
    retrieval_risk_high_threshold: float = Field(default=0.80, ge=0.0, le=1.0)
    semantic_classifier_enabled: bool = False
    semantic_classifier_timeout_seconds: float = Field(default=0.5, gt=0.0, le=30.0)
    semantic_positive_policy: Literal["high", "medium"] = "high"
    # Failure cannot authorize unresolved medium input; both levels block ON.
    semantic_fallback_policy: Literal["medium", "high"] = "medium"
    prompt_structure_check_enabled: bool = True
    action_gate_enabled: bool = True
    action_gate_require_provenance: bool = True

    @model_validator(mode="before")
    @classmethod
    def reject_retired_similarity_setting(cls, value):
        if isinstance(value, dict) and "prompt_leak_similarity_threshold" in value:
            raise ValueError(
                "prompt_leak_similarity_threshold is retired: no similarity model exists; "
                "use prompt_structure_check_enabled instead"
            )
        return value

    @field_validator("prompt_risk_weights")
    @classmethod
    def validate_prompt_risk_weights(cls, value: dict[str, float]) -> dict[str, float]:
        if any(weight < 0.0 or weight > 1.0 for weight in value.values()):
            raise ValueError("prompt_risk_weights phải nằm trong [0,1]")
        return value


@lru_cache(maxsize=8)
def _parse_security_settings(config_text: str, selected_mode: str) -> SecuritySettings:
    """Private validated template; public callers always receive a deep copy."""
    raw = yaml.safe_load(config_text) or {}
    security = dict(raw.get("security", {}))
    security["defense_enabled"] = selected_mode == "on"
    return SecuritySettings.model_validate(security)


def load_security_settings(mode: str | None = None) -> SecuritySettings:
    """Đọc defense_off/on YAML; argument hoặc env quyết định mode cuối cùng."""
    selected_mode = (mode or os.environ.get("DEFENSE_MODE", "off")).strip().lower()
    if selected_mode not in {"off", "on"}:
        raise ValueError("DEFENSE_MODE phải là 'off' hoặc 'on'")

    path = PROJECT_ROOT / "configs" / f"defense_{selected_mode}.yaml"
    # Read contents every time: edits cannot hide behind identical mtime/size,
    # and a missing/unreadable file still fails instead of returning stale policy.
    return _parse_security_settings(path.read_text(encoding="utf-8"), selected_mode).model_copy(deep=True)


def is_defense_enabled() -> bool:
    return load_security_settings().defense_enabled
