"""Wrapper embedding được cấu hình qua biến môi trường (Phase 4)."""

from __future__ import annotations

import os
from functools import lru_cache


def _env_flag(name: str, default: bool = False) -> bool:
    """Đọc biến môi trường boolean và báo rõ khi giá trị không hợp lệ."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(
        f"{name} phải là một trong: true/false, 1/0, yes/no, on/off"
    )


@lru_cache(maxsize=1)
def get_embedding_function():
    """Trả LangChain Embeddings object.

    Baseline mặc định dùng Google Gemini Embedding và tái sử dụng API_KEY
    của LLM nếu EMBEDDING_API_KEY để trống.
    """
    provider = os.environ.get("EMBEDDING_PROVIDER", "google").strip().lower()
    model_name = os.environ.get("EMBEDDING_MODEL", "gemini-embedding-2").strip()

    if provider in {"google", "gemini"}:
        api_key = (
            os.environ.get("EMBEDDING_API_KEY")
            or os.environ.get("API_KEY")
            or os.environ.get("GOOGLE_API_KEY")
            or os.environ.get("GEMINI_API_KEY")
        )
        if not api_key:
            raise ValueError(
                "Thiếu API key cho embedding. Điền API_KEY trong .env "
                "hoặc EMBEDDING_API_KEY nếu muốn dùng key riêng."
            )

        # Tích hợp hiện tại tự đọc GOOGLE_API_KEY/GEMINI_API_KEY.
        # setdefault chỉ đưa key từ API_KEY vào môi trường của process, không ghi file.
        os.environ.setdefault("GOOGLE_API_KEY", api_key)
        from langchain_google_genai import GoogleGenerativeAIEmbeddings

        return GoogleGenerativeAIEmbeddings(model=model_name)

    if provider == "local":
        local_files_only = _env_flag("EMBEDDING_LOCAL_FILES_ONLY", False)
        if local_files_only:
            # Các biến này phải được đặt trước khi import Hugging Face để tránh
            # HEAD request, log retry và progress bar khi model đã có trong cache.
            os.environ.setdefault("HF_HUB_OFFLINE", "1")
            os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
            os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
        try:
            from langchain_huggingface import HuggingFaceEmbeddings
        except ImportError as exc:
            raise ImportError(
                "EMBEDDING_PROVIDER=local cần cài: "
                "pip install langchain-huggingface sentence-transformers"
            ) from exc
        try:
            return HuggingFaceEmbeddings(
                model_name=model_name,
                model_kwargs={"local_files_only": local_files_only},
                show_progress=False,
            )
        except OSError as exc:
            if local_files_only:
                raise RuntimeError(
                    f"Không tìm thấy đầy đủ model {model_name!r} trong cache local. "
                    "Hãy đặt EMBEDDING_LOCAL_FILES_ONLY=false và chạy một lần "
                    "khi có mạng để tải model."
                ) from exc
            raise

    raise ValueError(
        f"EMBEDDING_PROVIDER không được hỗ trợ: {provider!r}. "
        "Dùng 'google' hoặc 'local'."
    )


def embed_documents(texts: list[str]) -> list[list[float]]:
    return get_embedding_function().embed_documents(texts)


def embed_query(text: str) -> list[float]:
    return get_embedding_function().embed_query(text)
