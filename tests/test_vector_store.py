"""Regression tests for Chroma collection metadata handling."""

from knowledge_base.vector_store import _validate_embedding_fingerprint


class _EmptyCollection:
    def __init__(self):
        self.metadata = {"hnsw:space": "cosine"}
        self.modified_metadata = None

    def count(self):
        return 0

    def modify(self, *, metadata):
        self.modified_metadata = metadata


def test_empty_collection_fingerprint_does_not_modify_hnsw_config(monkeypatch):
    monkeypatch.setenv("EMBEDDING_PROVIDER", "local")
    monkeypatch.setenv("EMBEDDING_MODEL", "BAAI/bge-m3")
    collection = _EmptyCollection()

    _validate_embedding_fingerprint(collection, 1024, allow_legacy=False)

    assert collection.modified_metadata == {
        "embedding_provider": "local",
        "embedding_model": "BAAI/bge-m3",
        "embedding_dimension": 1024,
    }
