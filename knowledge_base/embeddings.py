"""Embedding wrapper cấu hình qua biến môi trường (Phase 4)."""

from __future__ import annotations

import os
from functools import lru_cache


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

        # Integration hiện tại tự đọc GOOGLE_API_KEY/GEMINI_API_KEY.
        # setdefault chỉ đưa key từ API_KEY vào env của process, không ghi file.
        os.environ.setdefault("GOOGLE_API_KEY", api_key)
        from langchain_google_genai import GoogleGenerativeAIEmbeddings

        return GoogleGenerativeAIEmbeddings(model=model_name)

    if provider == "local":
        try:
            from langchain_huggingface import HuggingFaceEmbeddings
        except ImportError as exc:
            raise ImportError(
                "EMBEDDING_PROVIDER=local cần cài: "
                "pip install langchain-huggingface sentence-transformers"
            ) from exc
        return HuggingFaceEmbeddings(model_name=model_name)

    raise ValueError(
        f"EMBEDDING_PROVIDER không được hỗ trợ: {provider!r}. "
        "Dùng 'google' hoặc 'local'."
    )


def embed_documents(texts: list[str]) -> list[list[float]]:
    return get_embedding_function().embed_documents(texts)


def embed_query(text: str) -> list[float]:
    return get_embedding_function().embed_query(text)
