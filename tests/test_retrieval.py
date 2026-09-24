"""Unit tests không cần gọi API thật cho Phase 4."""

from knowledge_base.chunking import chunk_document
from knowledge_base.ingestion import ingest_jsonl_partitioned, validate_document
from knowledge_base.retrieval import rerank_results


def _doc(**overrides):
    base = {
        "document_id": "doc_test",
        "title": "Test",
        "source": "unit_test",
        "timestamp": "2026-08-20",
        "trust_level": 0.8,
        "document_type": "note",
        "topic": ["prompt_injection"],
        "content": "Prompt Injection " * 100,
    }
    base.update(overrides)
    return base


def test_validate_document_adds_hash():
    doc = validate_document(_doc(source="OWASP", trust_level=0.1))
    assert doc["content_hash"]
    assert doc["trust_level"] == 0.95
    assert doc["claimed_trust_level"] == 0.1
    assert doc["trust_managed"] is True
    assert doc["source_allowlisted"] is True


def test_unknown_source_cannot_self_assign_high_trust():
    doc = validate_document(_doc(source="attacker", trust_level=1.0))
    assert doc["trust_level"] == 0.0
    assert doc["claimed_trust_level"] == 1.0
    assert doc["trust_managed"] is True
    assert doc["source_allowlisted"] is False


def test_chunk_document_keeps_metadata():
    doc = validate_document(_doc())
    chunks = chunk_document(doc, chunk_size=120, overlap=20)
    assert len(chunks) > 1
    assert chunks[0]["document_id"] == "doc_test"
    assert chunks[0]["chunk_id"] == "doc_test_chunk_00"
    assert chunks[0]["content_hash"]
    assert chunks[0]["trust_managed"] is True
    assert chunks[0]["source_allowlisted"] is False


def test_unapproved_source_is_only_quarantined_when_enforced(tmp_path):
    path = tmp_path / "documents.jsonl"
    path.write_text(
        '{"document_id":"unknown","title":"Test","source":"attacker",'
        '"timestamp":"2026-09-15","trust_level":1.0,'
        '"document_type":"note","topic":["test"],"content":"Claim"}\n',
        encoding="utf-8",
    )

    monitor = ingest_jsonl_partitioned(
        path, enforce_source_allowlist=False
    )
    assert len(monitor.chunks) == 1
    assert monitor.quarantined == []

    enforced = ingest_jsonl_partitioned(
        path, enforce_source_allowlist=True
    )
    assert enforced.chunks == []
    assert enforced.quarantined[0]["quarantine_reason"] == (
        "source_not_allowlisted"
    )


def test_rerank_prefers_trusted_source_when_similarity_equal():
    items = [
        {"similarity_score": 0.9, "trust_level": 0.2},
        {"similarity_score": 0.9, "trust_level": 0.9},
    ]
    ranked = rerank_results(items, trust_aware=True)
    assert ranked[0]["trust_level"] == 0.9


def test_rerank_ignores_trust_when_defense_is_off():
    items = [
        {"similarity_score": 0.8, "trust_level": 1.0},
        {"similarity_score": 0.9, "trust_level": 0.0},
    ]
    ranked = rerank_results(items, trust_aware=False)
    assert ranked[0]["similarity_score"] == 0.9
