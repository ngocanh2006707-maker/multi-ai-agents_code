"""Build Knowledge Base Phase 4.

Chạy mặc định:
    python scripts_build_kb.py --reset

Hoặc dùng file JSONL khác:
    python scripts_build_kb.py --input data/raw/my_documents.jsonl --reset
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from knowledge_base.embeddings import embed_documents
from knowledge_base.ingestion import ingest_jsonl
from knowledge_base.vector_store import collection_count, reset_vector_store, upsert_chunks

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        default="data/raw/seed_documents.jsonl",
        help="File JSONL chứa document nguồn",
    )
    parser.add_argument("--reset", action="store_true", help="Xóa collection cũ trước khi build")
    parser.add_argument("--chunk-size", type=int, default=900)
    parser.add_argument("--overlap", type=int, default=120)
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        raise FileNotFoundError(f"Không tìm thấy file: {input_path}")

    chunks = ingest_jsonl(input_path, chunk_size=args.chunk_size, overlap=args.overlap)
    if not chunks:
        raise ValueError("Không tạo được chunk nào từ input")

    if args.reset:
        reset_vector_store()

    print(f"Documents/chunks chuẩn bị index: {len(chunks)} chunks")
    print("Đang tạo embeddings bằng model đã cấu hình trong .env ...")
    vectors = embed_documents([chunk["content"] for chunk in chunks])
    written = upsert_chunks(chunks, vectors)

    print(f"Đã upsert: {written} chunks")
    print(f"Tổng số chunks trong collection: {collection_count()}")


if __name__ == "__main__":
    main()
