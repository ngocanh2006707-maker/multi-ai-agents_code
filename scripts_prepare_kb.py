"""Normalize an external KB JSONL and merge it with the baseline seed file.

This script is deliberately limited to the known documents in the current KB
import. It creates a backup before replacing the source JSONL, recalculates
content hashes, validates both the corrected and merged datasets, and refuses
to merge duplicate document IDs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import date
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from knowledge_base.ingestion import ingest_jsonl, load_jsonl, validate_document


ARXIV_PUBLISHED_DATES = {
    "doc_003": "2024-10-09",
    "doc_005": "2025-03-27",
    "doc_006": "2025-03-12",
    "doc_007": "2025-06-06",
}

OWASP_REVISIONS = {
    "doc_001": {
        "date": "2026-06-27",
        "commit": "9feea5a6b5afdeb3277ad5f49262a62f86e018fb",
        "path": "cheatsheets/AI_Agent_Security_Cheat_Sheet.md",
    },
    "doc_002": {
        "date": "2026-04-28",
        "commit": "3b50b149db79717c14fca003670c27a2ddb7df40",
        "path": "cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.md",
    },
}

TOPIC_FIXES = {
    "doc_001": [
        "agentic_security",
        "prompt_injection",
        "least_privilege",
        "agent_isolation",
        "tool_security",
        "defense",
    ],
    "doc_002": [
        "prompt_injection",
        "direct_prompt_injection",
        "indirect_prompt_injection",
        "input_validation",
        "defense",
    ],
    "doc_003": ["prompt_injection", "agent_to_agent_prompt_injection"],
    "doc_004": ["prompt_injection"],
    "doc_005": ["data_poisoning"],
    "doc_006": ["data_poisoning", "defense"],
    "doc_007": [
        "data_poisoning",
        "knowledge_poisoning",
        "rag_security",
        "poisoned_rag",
    ],
    "doc_008": ["data_poisoning"],
    "doc_009": [
        "agentic_security",
        "prompt_injection",
        "tool_security",
        "least_privilege",
        "knowledge_poisoning",
        "defense",
    ],
}


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _without_tracking(url: str) -> str:
    parts = urlsplit(url)
    query = urlencode(
        [
            (key, value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
            if not key.lower().startswith("utm_")
        ]
    )
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _read_official_markdown(path: Path, expected_title: str) -> str:
    content = path.read_text(encoding="utf-8").lstrip("\ufeff").strip()
    if not content.startswith(f"# {expected_title}"):
        raise ValueError(
            f"Nguon OWASP {path} khong co title mong doi: {expected_title!r}"
        )
    return content + "\n"


def _write_jsonl(path: Path, documents: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(
        json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n"
        for document in documents
    )
    path.write_text(payload, encoding="utf-8", newline="\n")


def _validate_dates(documents: list[dict]) -> None:
    for document in documents:
        try:
            date.fromisoformat(str(document["timestamp"]))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"timestamp khong phai ISO date: {document.get('document_id')}"
            ) from exc


def normalize_documents(
    documents: list[dict],
    official_agent_cheatsheet: Path,
    official_injection_cheatsheet: Path,
) -> list[dict]:
    expected_ids = {f"doc_{index:03d}" for index in range(1, 10)}
    actual_ids = {str(document.get("document_id", "")) for document in documents}
    if actual_ids != expected_ids:
        raise ValueError(
            f"Tap document khong dung 9 ID mong doi: {sorted(actual_ids)}"
        )

    official_content = {
        "doc_001": _read_official_markdown(
            official_agent_cheatsheet, "AI Agent Security Cheat Sheet"
        ),
        "doc_002": _read_official_markdown(
            official_injection_cheatsheet,
            "LLM Prompt Injection Prevention Cheat Sheet",
        ),
    }

    normalized: list[dict] = []
    for original in documents:
        document = dict(original)
        document_id = document["document_id"]

        document["source"] = "OWASP" if document["source"] == "OWSAP" else document["source"]
        document["url"] = _without_tracking(str(document.get("url", "")))
        document["topic"] = TOPIC_FIXES[document_id]

        if document_id in ARXIV_PUBLISHED_DATES:
            document["timestamp"] = ARXIV_PUBLISHED_DATES[document_id]
        elif document_id in OWASP_REVISIONS:
            revision = OWASP_REVISIONS[document_id]
            document["timestamp"] = revision["date"]
            document["url"] = (
                "https://github.com/OWASP/CheatSheetSeries/blob/"
                f"{revision['commit']}/{revision['path']}"
            )
            document["content"] = official_content[document_id]
            document["notes"] = (
                str(document.get("notes", "")).rstrip(". ")
                + f"; pinned to OWASP revision {revision['commit']}."
            )
        else:
            # Remaining dates were correct but lacked zero padding.
            document["timestamp"] = date.fromisoformat(
                "-".join(
                    [
                        str(document["timestamp"]).split("-")[0],
                        str(document["timestamp"]).split("-")[1].zfill(2),
                        str(document["timestamp"]).split("-")[2].zfill(2),
                    ]
                )
            ).isoformat()

        document["content_hash"] = _sha256(str(document["content"]))
        validate_document(document)
        normalized.append(document)

    _validate_dates(normalized)
    return normalized


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--documents", required=True, type=Path)
    parser.add_argument("--seed", default="data/raw/seed_documents.jsonl", type=Path)
    parser.add_argument(
        "--output", default="data/raw/combined_documents.jsonl", type=Path
    )
    parser.add_argument("--agent-cheatsheet", required=True, type=Path)
    parser.add_argument("--injection-cheatsheet", required=True, type=Path)
    args = parser.parse_args()

    incoming = normalize_documents(
        load_jsonl(args.documents),
        args.agent_cheatsheet,
        args.injection_cheatsheet,
    )

    backup = args.documents.with_name(args.documents.name + ".pre_kb_fix.bak")
    if not backup.exists():
        shutil.copy2(args.documents, backup)
    _write_jsonl(args.documents, incoming)

    # Re-read the replaced source before merge so the on-disk artifact itself is tested.
    corrected = load_jsonl(args.documents)
    ingest_jsonl(args.documents)
    seed = load_jsonl(args.seed)
    combined = seed + corrected
    ids = [str(document.get("document_id", "")).strip() for document in combined]
    if len(ids) != len(set(ids)):
        duplicates = sorted({item for item in ids if ids.count(item) > 1})
        raise ValueError(f"document_id trung khi merge: {duplicates}")

    _write_jsonl(args.output, combined)
    chunks = ingest_jsonl(args.output)
    print(f"Corrected documents: {len(corrected)}")
    print(f"Backup: {backup}")
    print(f"Merged documents: {len(combined)}")
    print(f"Validated chunks: {len(chunks)}")
    print(f"Output: {args.output.resolve()}")


if __name__ == "__main__":
    main()
