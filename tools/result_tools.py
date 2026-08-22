"""Tool lưu kết quả thí nghiệm vào vùng data/results được giới hạn."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


RESULTS_ROOT = (Path(__file__).resolve().parents[1] / "data" / "results").resolve()
MAX_RESULT_BYTES = 1_000_000


def _resolve_result_path(path: str) -> Path:
    if not isinstance(path, str) or not path.strip():
        raise ValueError("Result path không được rỗng")
    requested = Path(path.strip())
    if requested.is_absolute():
        raise PermissionError("Result path phải là đường dẫn tương đối")
    if requested.suffix.lower() != ".json":
        raise ValueError("Kết quả chỉ được lưu ở định dạng .json")

    resolved = (RESULTS_ROOT / requested).resolve()
    try:
        resolved.relative_to(RESULTS_ROOT)
    except ValueError as exc:
        raise PermissionError("Chỉ được lưu kết quả trong data/results/") from exc
    return resolved


def save_test_result(result: dict[str, Any], path: str) -> dict[str, Any]:
    """Lưu JSON theo chế độ create-only để không ghi đè dữ liệu hiện có."""
    if not isinstance(result, dict):
        raise TypeError("result phải là dict")
    serialized = json.dumps(
        result,
        ensure_ascii=False,
        indent=2,
        allow_nan=False,
    )
    encoded = serialized.encode("utf-8")
    if len(encoded) > MAX_RESULT_BYTES:
        raise ValueError(f"Kết quả vượt giới hạn {MAX_RESULT_BYTES} bytes")

    target = _resolve_result_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open("x", encoding="utf-8", newline="\n") as file:
            file.write(serialized)
            file.write("\n")
    except FileExistsError as exc:
        raise FileExistsError(
            f"File kết quả đã tồn tại, không được ghi đè: {path}"
        ) from exc

    return {
        "path": target.relative_to(RESULTS_ROOT).as_posix(),
        "bytes_written": len(encoded) + 1,
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }
