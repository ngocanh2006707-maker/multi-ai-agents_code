import json

import pytest

from tools import result_tools


def test_save_test_result_is_scoped_and_create_only(tmp_path, monkeypatch):
    root = (tmp_path / "results").resolve()
    monkeypatch.setattr(result_tools, "RESULTS_ROOT", root)

    saved = result_tools.save_test_result(
        {"metric": "attack_success_rate", "value": 0.5},
        "run_001.json",
    )
    content = json.loads((root / "run_001.json").read_text(encoding="utf-8"))
    assert saved["path"] == "run_001.json"
    assert content["value"] == 0.5

    with pytest.raises(FileExistsError, match="không được ghi đè"):
        result_tools.save_test_result({"value": 1.0}, "run_001.json")


def test_save_test_result_blocks_traversal_and_non_json(tmp_path, monkeypatch):
    monkeypatch.setattr(result_tools, "RESULTS_ROOT", (tmp_path / "results").resolve())
    with pytest.raises(PermissionError):
        result_tools.save_test_result({"value": 1}, "../outside.json")
    with pytest.raises(ValueError, match=r"\.json"):
        result_tools.save_test_result({"value": 1}, "result.txt")
