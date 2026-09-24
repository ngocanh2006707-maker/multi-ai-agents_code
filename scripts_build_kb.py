"""Build Knowledge Base Phase 4.

Chạy mặc định:
    python scripts_build_kb.py --reset

Hoặc dùng file JSONL khác:
    python scripts_build_kb.py --input data/raw/my_documents.jsonl --reset
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

from knowledge_base.embeddings import embed_documents
from knowledge_base.ingestion import ingest_jsonl_partitioned
from security.config import load_security_settings
from knowledge_base.vector_store import collection_count, reset_vector_store, upsert_chunks

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def main():
    # Tránh làm thay đổi environment chỉ vì module được import bởi test/tool.
    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        default="data/raw/seed_documents.jsonl",
        help="File JSONL chứa document nguồn",
    )
    parser.add_argument("--reset", action="store_true", help="Xóa collection cũ trước khi build")
    parser.add_argument("--chunk-size", type=int, default=900)
    parser.add_argument("--overlap", type=int, default=120)
    parser.add_argument(
        "--quarantine-output",
        help="File JSONL lưu tài liệu nguồn chưa được duyệt khi Defense On",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Không tìm thấy file: {input_path}")

    settings = load_security_settings()
    enforce_allowlist = (
        settings.defense_enabled and settings.require_allowlisted_source
    )
    batch = ingest_jsonl_partitioned(
        input_path,
        chunk_size=args.chunk_size,
        overlap=args.overlap,
        enforce_source_allowlist=enforce_allowlist,
        use_managed_trust=(
            settings.defense_enabled and settings.require_managed_trust
        ),
    )
    chunks = batch.chunks
    if batch.quarantined:
        quarantine_path = (
            Path(args.quarantine_output)
            if args.quarantine_output
            else Path("artifacts/quarantine") / (
                f"{input_path.stem}_"
                f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.jsonl"
            )
        )
        quarantine_path.parent.mkdir(parents=True, exist_ok=True)
        quarantine_path.write_text(
            "".join(
                json.dumps(item, ensure_ascii=False) + "\n"
                for item in batch.quarantined
            ),
            encoding="utf-8",
        )
        print(
            f"Đã cách ly {len(batch.quarantined)} documents tại: "
            f"{quarantine_path}"
        )
    if not chunks:
        raise ValueError(
            "Không có tài liệu được phép để tạo chunk; "
            "KB hiện tại chưa bị thay đổi."
        )

    print(f"Documents/chunks chuẩn bị index: {len(chunks)} chunks")
    print("Đang tạo embeddings bằng model đã cấu hình trong .env ...")
    vectors = embed_documents([chunk["content"] for chunk in chunks])

    # Chỉ xóa collection cũ sau khi embeddings đã tạo thành công. Nếu provider
    # lỗi, hết quota hoặc local model không load được, KB hiện tại vẫn được giữ.
    if args.reset:
        reset_vector_store()

    written = upsert_chunks(chunks, vectors)

    print(f"Đã upsert: {written} chunks")
    print(f"Tổng số chunks trong collection: {collection_count()}")


if __name__ == "__main__":
    main()
