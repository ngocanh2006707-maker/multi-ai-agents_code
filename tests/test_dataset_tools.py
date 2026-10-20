import json

import pytest

from tools import dataset_tools


@pytest.fixture
def isolated_data_root(tmp_path, monkeypatch):
    root = tmp_path / "data"
    root.mkdir()
    monkeypatch.setattr(dataset_tools, "DATA_ROOT", root.resolve())
    return root


def test_read_csv_dataset(isolated_data_root):
    path = isolated_data_root / "results.csv"
    path.write_text("attacked,blocked\n1,0\n0,1\n", encoding="utf-8")

    result = dataset_tools.read_dataset("results.csv")

    assert result["format"] == "csv"
    assert result["record_count"] == 2
    assert result["fields"] == ["attacked", "blocked"]
    assert "records" not in result


def test_read_json_and_jsonl(isolated_data_root):
    (isolated_data_root / "items.json").write_text(
        json.dumps([{"value": 1}, {"value": 2}]), encoding="utf-8"
    )
    (isolated_data_root / "items.jsonl").write_text(
        '{"value": 1}\n{"value": 2}\n', encoding="utf-8"
    )

    assert dataset_tools.read_dataset("items.json")["record_count"] == 2
    assert dataset_tools.read_dataset("items.jsonl")["record_count"] == 2


def test_read_dataset_blocks_path_traversal(isolated_data_root, tmp_path):
    outside = tmp_path / "secret.json"
    outside.write_text("{}", encoding="utf-8")

    with pytest.raises(PermissionError):
        dataset_tools.read_dataset("../secret.json")


def test_read_dataset_rejects_unsupported_extension(isolated_data_root):
    (isolated_data_root / "script.py").write_text("print('no')", encoding="utf-8")

    with pytest.raises(ValueError):
        dataset_tools.read_dataset("script.py")


def test_read_dataset_rejects_absolute_path(isolated_data_root):
    path = isolated_data_root / "items.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(PermissionError, match="đường dẫn tương đối"):
        dataset_tools.read_dataset(str(path.resolve()))


def test_read_dataset_enforces_file_and_record_limits(
    isolated_data_root, monkeypatch
):
    oversized = isolated_data_root / "oversized.json"
    oversized.write_text('[{"value": 1}]', encoding="utf-8")
    monkeypatch.setattr(dataset_tools, "MAX_DATASET_FILE_BYTES", 5)
    with pytest.raises(ValueError, match="Dataset vượt giới hạn"):
        dataset_tools.read_dataset("oversized.json")

    monkeypatch.setattr(dataset_tools, "MAX_DATASET_FILE_BYTES", 1_000)
    monkeypatch.setattr(dataset_tools, "MAX_DATASET_RECORDS", 1)
    records = isolated_data_root / "records.json"
    records.write_text('[{"value": 1}, {"value": 2}]', encoding="utf-8")
    with pytest.raises(ValueError, match="records"):
        dataset_tools.read_dataset("records.json")
