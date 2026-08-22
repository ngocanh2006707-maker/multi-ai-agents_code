"""CLI entrypoint chạy một câu hỏi qua compiled LangGraph workflow."""

import argparse
import sys

from dotenv import load_dotenv

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

load_dotenv()

from graph.workflow import build_workflow


def main() -> None:
    """Nhận một câu hỏi và chạy qua compiled LangGraph workflow."""
    parser = argparse.ArgumentParser(
        description="Multi-Agent AI Security Research Assistant"
    )
    parser.add_argument(
        "query",
        nargs="?",
        help="Câu hỏi. Nếu bỏ trống, chương trình sẽ hỏi qua stdin.",
    )
    args = parser.parse_args()

    query = (args.query or input("Nhập câu hỏi: ")).strip()
    if not query:
        parser.error("Câu hỏi không được rỗng")

    result = build_workflow().invoke({
        "user_query": query,
        "current_agent": None,
        "errors": [],
    })
    print(result.get("final_answer", "Không có câu trả lời."))

    if result.get("errors"):
        print("\nErrors:", file=sys.stderr)
        for error in result["errors"]:
            print(f"- {error}", file=sys.stderr)


if __name__ == "__main__":
    main()
