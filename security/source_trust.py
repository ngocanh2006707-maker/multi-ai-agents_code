"""Gán trust từ registry do hệ thống quản lý, không tin metadata đầu vào."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from security.config import PROJECT_ROOT


SOURCE_TRUST_POLICY_ID = "source_trust_registry_v1"
DEFAULT_POLICY_PATH = PROJECT_ROOT / "configs" / "source_trust.yaml"


@dataclass(frozen=True)
class TrustAssignment:
    trust_level: float
    registered: bool
    allowed: bool
    policy_id: str = SOURCE_TRUST_POLICY_ID


def _validated_trust(value: object, *, label: str) -> float:
    try:
        trust = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} phải là số trong [0, 1]") from exc
    if not 0.0 <= trust <= 1.0:
        raise ValueError(f"{label} phải nằm trong [0, 1]")
    return trust


@lru_cache(maxsize=1)
def load_source_trust_policy(path: str | Path = DEFAULT_POLICY_PATH) -> dict:
    """Đọc và kiểm tra registry trust thuộc quyền quản lý của hệ thống."""
    policy_path = Path(path)
    with policy_path.open("r", encoding="utf-8") as file:
        raw = yaml.safe_load(file) or {}

    default_trust = _validated_trust(
        raw.get("default_trust_level", 0.0), label="default_trust_level"
    )
    raw_sources = raw.get("sources", {})
    if not isinstance(raw_sources, dict):
        raise ValueError("source_trust.sources phải là mapping")

    sources: dict[str, dict[str, object]] = {}
    for raw_name, raw_settings in raw_sources.items():
        name = str(raw_name).strip()
        if not name:
            raise ValueError("Tên source trong registry không được rỗng")
        if not isinstance(raw_settings, dict):
            raise ValueError(f"Cấu hình source {name!r} phải là mapping")
        sources[name] = {
            "trust_level": _validated_trust(
                raw_settings.get("trust_level"),
                label=f"sources.{name}.trust_level",
            ),
            "allowed": raw_settings.get("allowed") is True,
        }

    return {
        "version": int(raw.get("version", 1)),
        "default_trust_level": default_trust,
        "sources": sources,
    }


def assign_system_trust(source: str) -> TrustAssignment:
    """Gán trust theo source; nguồn lạ nhận mức mặc định fail-closed."""
    normalized_source = str(source or "").strip()
    policy = load_source_trust_policy()
    source_settings = policy["sources"].get(normalized_source)
    if source_settings is None:
        return TrustAssignment(
            trust_level=policy["default_trust_level"],
            registered=False,
            allowed=False,
        )
    return TrustAssignment(
        trust_level=source_settings["trust_level"],
        registered=True,
        allowed=source_settings["allowed"],
    )
