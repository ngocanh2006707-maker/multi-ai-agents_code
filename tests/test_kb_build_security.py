"""Kiểm tra build KB fail-closed trước khi gọi embedding/vector store."""

import json
import sys
from unittest.mock import patch

import pytest

from scripts_build_kb import main


def test_defense_on_quarantines_unapproved_source_before_embedding(
    tmp_path, monkeypatch
):
    source = tmp_path / "unapproved.jsonl"
    quarantine = tmp_path / "quarantine.jsonl"
    source.write_text(
        json.dumps({
            "document_id": "unknown",
            "title": "Unapproved",
            "source": "attacker",
            "timestamp": "2026-09-15",
            "trust_level": 1.0,
            "document_type": "note",
            "topic": ["test"],
            "content": "Unverified claim.",
        }) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("DEFENSE_MODE", "on")
    monkeypatch.setattr(sys, "argv", [
        "scripts_build_kb.py",
        "--input",
        str(source),
        "--quarantine-output",
        str(quarantine),
    ])

    with patch("scripts_build_kb.embed_documents") as embed, \
         patch("scripts_build_kb.reset_vector_store") as reset, \
         patch("scripts_build_kb.upsert_chunks") as upsert, \
         pytest.raises(ValueError, match="Không có tài liệu được phép"):
        main()

    embed.assert_not_called()
    reset.assert_not_called()
    upsert.assert_not_called()
    record = json.loads(quarantine.read_text(encoding="utf-8"))
    assert record["quarantine_reason"] == "source_not_allowlisted"
    assert record["document"]["trust_level"] == 0.0
    assert record["document"]["claimed_trust_level"] == 1.0


def test_defense_off_keeps_unapproved_source_for_monitoring(
    tmp_path, monkeypatch
):
    source = tmp_path / "unapproved.jsonl"
    source.write_text(
        json.dumps({
            "document_id": "unknown",
            "title": "Unapproved",
            "source": "attacker",
            "timestamp": "2026-09-15",
            "trust_level": 1.0,
            "document_type": "note",
            "topic": ["test"],
            "content": "Unverified claim.",
        }) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("DEFENSE_MODE", "off")
    monkeypatch.setattr(sys, "argv", [
        "scripts_build_kb.py", "--input", str(source)
    ])

    with patch("scripts_build_kb.embed_documents", return_value=[[0.1, 0.2]]), \
         patch("scripts_build_kb.upsert_chunks", return_value=1) as upsert, \
         patch("scripts_build_kb.collection_count", return_value=1):
        main()

    chunks = upsert.call_args.args[0]
    assert chunks[0]["source_allowlisted"] is False
    assert chunks[0]["trust_level"] == 1.0
    assert chunks[0]["trust_managed"] is False
