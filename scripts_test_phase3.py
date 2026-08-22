"""
Chạy: python scripts_test_phase3.py
(cần đã pip install -r requirements.txt và điền API_KEY trong .env)

Test Planner với các câu hỏi đơn giản để kiểm tra:
1. LLM phân loại route có hợp lý không.
2. Planner build đúng plan (hàng đợi worker) theo route.
3. Vòng lặp next_agent dừng đúng lúc.

Vì Research/Analyst/Executor CHƯA triển khai (Phase 4-6), script này giả
lập worker bằng cách chỉ set current_agent — mục tiêu là kiểm tra ĐIỀU
PHỐI, chưa kiểm tra nội dung câu trả lời thật.
"""

import sys

from dotenv import load_dotenv

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
load_dotenv()

from agents.planner import planner_node

TEST_QUERIES = [
    "Xin chào, bạn có thể giúp gì cho tôi?",
    "Prompt Injection là gì?",
    "So sánh Input Validation và Least Privilege trong bảo mật AI Agent",
    "Công thức nấu phở bò truyền thống là gì?",
    "Hãy đọc dataset test_attacks.csv và tính accuracy",
]


def run_one(user_query: str):
    print(f"\n{'='*70}\nCâu hỏi: {user_query}\n{'='*70}")

    state = {"user_query": user_query, "current_agent": None}
    state = planner_node(state)
    print(f"  -> route xác định: {state['route']}")
    print(f"  -> plan: {state['plan']}")
    print(f"  -> next_agent: {state['next_agent']}")

    step = 1
    while state["next_agent"] != "final":
        worker = state["next_agent"]
        print(f"  [Lượt {step}] (giả lập) {worker} chạy xong -> quay lại Planner")
        state = {**state, "current_agent": worker}
        # Mô phỏng contract output tối thiểu để Planner có thể kiểm tra Worker.
        if worker == "research":
            state["retrieved_documents"] = [
                {
                    "document_id": "phase3_mock",
                    "chunk_id": "phase3_mock_chunk_00",
                    "title": "Phase 3 mock document",
                    "source": "scripts_test_phase3",
                    "trust_level": 1.0,
                    "similarity_score": 1.0,
                    "content": "Dữ liệu giả lập để kiểm tra điều phối Planner.",
                }
            ]
        elif worker == "analyst":
            state["analysis_result"] = {
                "topic": "Phase 3 mock analysis",
                "summary": "Kết quả giả lập để kiểm tra điều phối.",
                "comparison": [],
                "contradictions": [],
                "recommendation": "Không dùng cho đánh giá nội dung.",
                "confidence": 1.0,
            }
        elif worker == "executor":
            state["execution_result"] = {
                "status": "success",
                "tool": state.get("execution_request", {}).get("tool_name", "mock"),
                "result": {"phase3_mock": True},
                "error": None,
            }
        state = planner_node(state)
        print(f"           plan còn lại: {state['plan']}, next_agent: {state['next_agent']}")
        step += 1

    print(f"\n  FINAL ANSWER:\n  {state['final_answer']}")


if __name__ == "__main__":
    for q in TEST_QUERIES:
        run_one(q)
