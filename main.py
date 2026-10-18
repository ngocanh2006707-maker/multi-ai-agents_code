"""Điểm vào CLI chạy một câu hỏi qua workflow LangGraph đã biên dịch."""

import argparse
import json
import os
from pathlib import Path
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
    parser.add_argument(
        "--execution-input", type=Path,
        help="File JSON chứa tool_name và params do caller xác nhận trước planning; cần cho tool ở Defense ON.",
    )
    parser.add_argument(
        "--demo-app-prompt-disclosure", action="store_true",
        help="Demo OFF: debug handler cố ý tiết lộ prompt ứng dụng; không phải tấn công model.",
    )
    args = parser.parse_args()
    if args.demo_app_prompt_disclosure:
        from graph.baseline import APP_PROMPT_DEMO_ENV
        os.environ[APP_PROMPT_DEMO_ENV] = "1"
        print("DEMO: tiết lộ prompt ứng dụng qua debug handler chỉ hoạt động ở OFF.", file=sys.stderr)

    query = (args.query or input("Nhập câu hỏi: ")).strip()
    if not query:
        parser.error("Câu hỏi không được rỗng")

    public_input = {
        "user_query": query,
        "current_agent": None,
        "errors": [],
    }
    if args.execution_input is not None:
        try:
            public_input["execution_input"] = json.loads(args.execution_input.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            parser.error("Không đọc được file execution input JSON hợp lệ.")
    result = build_workflow().invoke(public_input)
    print(result.get("final_answer", "Không có câu trả lời."))

    if result.get("errors"):
        print("\nErrors:", file=sys.stderr)
        for error in result["errors"]:
            print(f"- {error}", file=sys.stderr)


if __name__ == "__main__":
    main()
