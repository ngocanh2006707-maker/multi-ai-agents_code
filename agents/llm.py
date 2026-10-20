"""Client LLM dùng chung cho các Agent.

Mọi thông tin nhạy cảm lấy từ biến môi trường. Không hard-code API key.
Phase 3 mặc định dùng Google Gemini Developer API.
"""

import os
from functools import lru_cache


@lru_cache(maxsize=1)
def get_llm():
    """Trả về chat model đã cấu hình và cache để tái sử dụng."""
    provider = os.environ.get("MODEL_PROVIDER", "google").strip().lower()
    model_name = os.environ.get("MODEL_NAME", "gemini-3.1-flash-lite").strip()
    api_key = (
        os.environ.get("API_KEY")
        or os.environ.get("GOOGLE_API_KEY")
        or os.environ.get("GEMINI_API_KEY")
    )

    if provider in {"google", "gemini"}:
        if not api_key:
            raise ValueError(
                "Thiếu API key. Hãy điền API_KEY=... trong file .env "
                "(hoặc GOOGLE_API_KEY/GEMINI_API_KEY)."
            )
        from langchain_google_genai import ChatGoogleGenerativeAI

        return ChatGoogleGenerativeAI(
            model=model_name,
            api_key=api_key,
            temperature=0,
        )

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        return ChatAnthropic(model=model_name, api_key=api_key, temperature=0)

    if provider == "openai":
        from langchain_openai import ChatOpenAI

        return ChatOpenAI(model=model_name, api_key=api_key, temperature=0)

    raise ValueError(
        f"MODEL_PROVIDER không được hỗ trợ: {provider!r}. "
        "Dùng 'google', 'anthropic' hoặc 'openai'."
    )
