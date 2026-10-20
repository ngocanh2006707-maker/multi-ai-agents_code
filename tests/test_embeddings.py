"""Kiểm tra cấu hình wrapper embedding mà không tải model thật."""

import os
from types import ModuleType
import sys

import pytest

from knowledge_base.embeddings import _env_flag, get_embedding_function


def test_local_embedding_offline_mode_uses_cache_and_suppresses_hub_output(
    monkeypatch,
):
    captured = {}
    fake_module = ModuleType("langchain_huggingface")

    class FakeHuggingFaceEmbeddings:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    fake_module.HuggingFaceEmbeddings = FakeHuggingFaceEmbeddings
    monkeypatch.setitem(sys.modules, "langchain_huggingface", fake_module)
    monkeypatch.setenv("EMBEDDING_PROVIDER", "local")
    monkeypatch.setenv("EMBEDDING_MODEL", "BAAI/bge-m3")
    monkeypatch.setenv("EMBEDDING_LOCAL_FILES_ONLY", "true")
    monkeypatch.delenv("HF_HUB_OFFLINE", raising=False)
    monkeypatch.delenv("HF_HUB_DISABLE_PROGRESS_BARS", raising=False)
    monkeypatch.delenv("TRANSFORMERS_VERBOSITY", raising=False)
    get_embedding_function.cache_clear()

    try:
        get_embedding_function()
    finally:
        get_embedding_function.cache_clear()

    assert captured == {
        "model_name": "BAAI/bge-m3",
        "model_kwargs": {"local_files_only": True},
        "show_progress": False,
    }
    assert os.environ["HF_HUB_OFFLINE"] == "1"
    assert os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] == "1"
    assert os.environ["TRANSFORMERS_VERBOSITY"] == "error"


def test_env_flag_rejects_invalid_value(monkeypatch):
    monkeypatch.setenv("EMBEDDING_LOCAL_FILES_ONLY", "sometimes")

    with pytest.raises(ValueError, match="EMBEDDING_LOCAL_FILES_ONLY"):
        _env_flag("EMBEDDING_LOCAL_FILES_ONLY")
