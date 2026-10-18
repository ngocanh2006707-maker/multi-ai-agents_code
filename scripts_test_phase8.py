"""Kiểm thử nghiệm thu tracing trên workflow LangGraph đã biên dịch."""

import argparse
import json
import sys

from dotenv import load_dotenv

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

load_dotenv()

from graph.workflow import build_workflow
from tracing.logger import get_trace_file


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--full-flow",
        action="store_true",
        help=(
            "Chạy Planner-Research-Analyst. Tùy chọn này gửi retrieved context "
            "tới LLM provider đã cấu hình."
        ),
    )
    args = parser.parse_args()
    query = (
        "So sánh Input Validation và Least Privilege để phòng Prompt Injection."
        if args.full_flow
        else "Giá Bitcoin hôm nay bao nhiêu?"
    )
    result = build_workflow().invoke({
        "user_query": query,
        "current_agent": None,
        "errors": [],
    })
    trace_id = result["trace_id"]
    events = []
    for line in get_trace_file().read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        if event.get("trace_id") == trace_id:
            events.append(event)

    print("TRACE ID:", trace_id)
    print("FLOW:", " -> ".join(event["agent"] for event in events))
    print("SEQUENCES:", [event["sequence"] for event in events])
    print("TRACE FILE:", get_trace_file())
    print("FINAL:", result.get("final_answer"))

    if not events:
        raise RuntimeError("Không tìm thấy trace event của request vừa chạy")
    if [event["sequence"] for event in events] != list(range(1, len(events) + 1)):
        raise RuntimeError("Trace sequence không liên tục")


if __name__ == "__main__":
    main()
