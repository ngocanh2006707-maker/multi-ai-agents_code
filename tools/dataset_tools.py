"""
Tool: read_dataset — đọc dataset thí nghiệm (CSV/JSON) từ data/.
Chỉ đọc trong phạm vi thư mục data/ đã whitelist (path traversal guard
cần có khi bật DEFENSE_MODE=on).

Sẽ triển khai ở Phase 6.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


DATA_ROOT = (Path(__file__).resolve().parents[1] / "data").resolve()
SUPPORTED_EXTENSIONS = {".csv", ".json", ".jsonl"}
MAX_DATASET_FILE_BYTES = 5 * 1024 * 1024
MAX_DATASET_RECORDS = 10_000
MAX_JSONL_LINE_CHARS = 100_000


def _resolve_dataset_path(path: str) -> Path:
    """Resolve path và bảo đảm target nằm trong thư mục data/."""
    if not isinstance(path, str) or not path.strip():
        raise ValueError("Dataset path không được rỗng")

    requested = Path(path.strip())
    if requested.is_absolute():
        raise PermissionError("Dataset path phải là đường dẫn tương đối trong data/")
    candidate = DATA_ROOT / requested
    resolved = candidate.resolve()

    try:
        resolved.relative_to(DATA_ROOT)
    except ValueError as exc:
        raise PermissionError("Chỉ được đọc dataset nằm trong thư mục data/") from exc

    if not resolved.is_file():
        raise FileNotFoundError(f"Không tìm thấy dataset: {path}")
    if resolved.suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            f"Định dạng không được hỗ trợ: {resolved.suffix}. "
            f"Chỉ chấp nhận: {sorted(SUPPORTED_EXTENSIONS)}"
        )
    if resolved.stat().st_size > MAX_DATASET_FILE_BYTES:
        raise ValueError(
            f"Dataset vượt giới hạn {MAX_DATASET_FILE_BYTES} bytes"
        )
    return resolved


def _enforce_record_limit(records: list[Any]) -> list[Any]:
    if len(records) > MAX_DATASET_RECORDS:
        raise ValueError(
            f"Dataset vượt giới hạn {MAX_DATASET_RECORDS} records"
        )
    return records


def _read_json(path: Path) -> list[Any]:
    with path.open("r", encoding="utf-8-sig") as file:
        value = json.load(file)
    records = value if isinstance(value, list) else [value]
    return _enforce_record_limit(records)


def _read_jsonl(path: Path) -> list[Any]:
    records: list[Any] = []
    with path.open("r", encoding="utf-8-sig") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue
            if len(line) > MAX_JSONL_LINE_CHARS:
                raise ValueError(
                    f"JSONL dòng {line_number} vượt giới hạn "
                    f"{MAX_JSONL_LINE_CHARS} ký tự"
                )
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"JSONL lỗi tại dòng {line_number}: {exc}") from exc
            if len(records) > MAX_DATASET_RECORDS:
                raise ValueError(
                    f"Dataset vượt giới hạn {MAX_DATASET_RECORDS} records"
                )
    return records


def _load_dataset(path: str) -> tuple[Path, str, list[Any]]:
    """Đọc dataset đã giới hạn; dùng nội bộ bởi các tool tổng hợp an toàn."""
    resolved = _resolve_dataset_path(path)
    extension = resolved.suffix.lower()

    if extension == ".csv":
        records = []
        with resolved.open("r", encoding="utf-8-sig", newline="") as file:
            for record in csv.DictReader(file):
                records.append(record)
                if len(records) > MAX_DATASET_RECORDS:
                    raise ValueError(
                        f"Dataset vượt giới hạn {MAX_DATASET_RECORDS} records"
                    )
    elif extension == ".json":
        records = _read_json(resolved)
    else:
        records = _read_jsonl(resolved)
    return resolved, extension, records


def read_dataset(path: str) -> dict[str, Any]:
    """Đọc metadata dataset; không đưa raw records vào Agent state hoặc trace."""
    resolved, extension, records = _load_dataset(path)
    fields = sorted({
        str(key)
        for record in records
        if isinstance(record, dict)
        for key in record
    })

    return {
        "path": resolved.relative_to(DATA_ROOT).as_posix(),
        "format": extension.removeprefix("."),
        "record_count": len(records),
        "fields": fields,
        "contains_object_records": all(
            isinstance(record, dict) for record in records
        ),
    }
