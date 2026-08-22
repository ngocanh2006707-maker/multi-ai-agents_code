"""Unit tests không cần gọi API thật cho Phase 4."""

from knowledge_base.chunking import chunk_document
from knowledge_base.ingestion import validate_document
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
    doc = validate_document(_doc())
    assert doc["content_hash"]
    assert doc["trust_level"] == 0.8


def test_chunk_document_keeps_metadata():
    doc = validate_document(_doc())
    chunks = chunk_document(doc, chunk_size=120, overlap=20)
    assert len(chunks) > 1
    assert chunks[0]["document_id"] == "doc_test"
    assert chunks[0]["chunk_id"] == "doc_test_chunk_00"
    assert chunks[0]["content_hash"]


def test_rerank_prefers_trusted_source_when_similarity_equal():
    items = [
        {"similarity_score": 0.9, "trust_level": 0.2},
        {"similarity_score": 0.9, "trust_level": 0.9},
    ]
    ranked = rerank_results(items)
    assert ranked[0]["trust_level"] == 0.9
