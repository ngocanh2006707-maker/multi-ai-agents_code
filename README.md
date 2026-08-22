# Multi-Agent AI Security Research Assistant

Hệ thống đa tác tử theo kiến trúc **Centralized Orchestrator** để tra cứu,
phân tích và so sánh các biện pháp phòng thủ cho AI Agent / Multi-Agent
System, đồng thời chuẩn bị làm testbed cho Prompt Injection và
Data/Knowledge Poisoning.

## Trạng thái hiện tại

- [x] Phase 1 — Architecture
- [x] Phase 2 — Project skeleton
- [x] Phase 3 — Planner + router
  - Google Gemini Developer API
  - Model mặc định: `gemini-3.1-flash-lite`
  - API key chỉ lấy từ `.env`, không hard-code
- [x] Phase 4 — Knowledge Base tối thiểu + Research Agent
  - Validation + cleaning
  - Chunking
  - Google Gemini Embedding
  - Chroma persistent vector database
  - Semantic retrieval
  - Trust-aware reranking
  - Research Agent ghi kết quả vào shared state rồi quay lại Planner
- [x] Phase 5 — Analyst Agent
- [x] Phase 6 — Executor Agent + tool allowlist
- [x] Phase 7 — Ghép LangGraph hoàn chỉnh
- [x] Phase 8 — Logging / tracing
- [x] Phase 9 — Security testbed

## 1. Setup

Windows PowerShell / CMD:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Sau đó mở `.env` và chỉ cần điền API key của Google AI Studio:

```env
MODEL_PROVIDER=google
MODEL_NAME=gemini-3.1-flash-lite
API_KEY=YOUR_GOOGLE_AI_API_KEY

EMBEDDING_PROVIDER=google
EMBEDDING_MODEL=gemini-embedding-2
EMBEDDING_API_KEY=
```

`EMBEDDING_API_KEY` để trống thì Phase 4 tự dùng lại `API_KEY`.

## 2. Test riêng Phase 3

```bash
python scripts_test_phase3.py
```

Script này chỉ kiểm tra Planner phân route và plan. Worker vẫn được giả lập
cố ý để test Phase 3 độc lập.

## 3. Build Knowledge Base Phase 4

Project có sẵn file nhỏ để kiểm thử pipeline:

```text
data/raw/seed_documents.jsonl
```

Đây chỉ là **seed data cho baseline**, không phải Knowledge Base nghiên cứu
chính thức. Khi có KB thật, thay bằng file JSONL của bạn.

Build/index lần đầu:

```bash
python scripts_build_kb.py --reset
```

Pipeline đang chạy:

```text
JSONL Document
    ↓
Validation
    ↓
Cleaning
    ↓
Chunking
    ↓
Gemini Embedding
    ↓
Chroma Index
    ↓
data/vector_db/
```

Muốn build file khác:

```bash
python scripts_build_kb.py --input data/raw/my_documents.jsonl --reset
```

Schema document tối thiểu:

```json
{
  "document_id": "doc_001",
  "title": "...",
  "source": "...",
  "timestamp": "2026-08-20",
  "trust_level": 0.9,
  "document_type": "paper",
  "topic": ["prompt_injection", "defense"],
  "content": "...",
  "is_poisoned": false,
  "attack_type": null,
  "experiment_id": null
}
```

`content_hash` không bắt buộc trong file đầu vào: ingestion sẽ tự tính nếu
chưa có.

## 4. Test Phase 4

Sau khi build KB:

```bash
python scripts_test_phase4.py
```

Luồng test chính:

```text
USER
 ↓
Planner
 ↓
Research
 ↓
Knowledge Base / Chroma
 ↓
Research
 ↓
Planner
 ↓
Final Answer
```

Research Agent **không kết luận** và không gọi Analyst. Nó chỉ trả các chunk
cùng metadata/similarity score về Planner. Planner vẫn giữ quyền tạo câu
trả lời cuối.

## 5. Retrieval output

Mỗi kết quả Research trả dạng gần như:

```json
{
  "document_id": "doc_001",
  "chunk_id": "doc_001_chunk_00",
  "content": "...",
  "title": "...",
  "source": "...",
  "timestamp": "...",
  "trust_level": 0.9,
  "content_hash": "...",
  "similarity_score": 0.87
}
```

Retrieval lấy nhiều ứng viên hơn `top_k`, sau đó rerank theo:

```text
ranking_score = similarity_score × (0.70 + 0.30 × trust_level)
```

Mục đích là ưu tiên nguồn đáng tin nhưng chưa loại tuyệt đối nguồn trust thấp
ở baseline.

Các field thử nghiệm `is_poisoned`, `attack_type`, `experiment_id` vẫn được
lưu trong vector database để đánh giá sau này, nhưng **không trả cho Research
Agent**, tránh lộ ground truth trong thí nghiệm poisoning.

## 6. File quan trọng đã triển khai trong Phase 4

```text
knowledge_base/
├── ingestion.py       # validate, clean, đọc JSONL
├── chunking.py        # chia chunk + content hash
├── embeddings.py      # Google Gemini Embedding
├── vector_store.py    # Chroma persistent DB
└── retrieval.py       # semantic search + trust reranking

agents/
└── researcher.py      # Research Agent

scripts_build_kb.py    # build/index KB
scripts_test_phase4.py # test Planner -> Research -> Planner
```

## 7. Nguyên tắc kiến trúc vẫn giữ nguyên

```text
Research  -X-> Analyst
Analyst   -X-> Executor
Executor  -X-> Research
```

Worker không gọi trực tiếp nhau. Mọi kết quả worker phải quay lại Planner.
Phase 5 tiếp theo sẽ thêm Analyst Agent, lúc đó mới kiểm thử:

```text
Planner -> Research -> Planner -> Analyst -> Planner -> Final
```

## 8. Test Phase 5

Sau khi Knowledge Base đã được build, chạy:

```bash
python scripts_test_phase5.py
```

Analyst chỉ phân tích tài liệu do Research trả về và không gọi tool. Kết quả
được ghi vào `analysis_result`; Planner định dạng kết quả thành câu trả lời cuối.
Các chunk cùng `document_id` chỉ được tính là một nguồn khi tính confidence.

## 9. Test Phase 6

```bash
python scripts_test_phase6.py
```

Luồng mong đợi:

```text
Planner -> Executor -> Planner -> Final
```

Executor chỉ gọi tool đã đăng ký trong allowlist khóa sau bootstrap. Hệ thống
cho phép `read_dataset`, `calculate_metrics`, `calculate_metrics_from_dataset`,
`run_security_test` và `save_test_result`; các tool nguy hiểm như `shell`,
`delete_file`, `read_secret` và `send_network_request` bị từ chối.

## 10. Chạy compiled LangGraph workflow

Chạy một câu hỏi từ CLI:

```bash
python main.py "Direct Prompt Injection là gì?"
```

Chạy acceptance test Phase 7:

```bash
python scripts_test_phase7.py
```

Graph sử dụng Centralized Orchestrator: mọi Worker luôn quay về Planner;
không có edge trực tiếp giữa Research, Analyst và Executor.

## 11. Logging và tracing

Mỗi request tự sinh một `trace_id`. Mỗi lần chạy node ghi một JSON object vào:

```text
tracing/logs/agent_trace.jsonl
```

Mỗi event có `sequence`, UTC `timestamp`, `agent`, input/output đã redaction,
route, `latency`, `latency_ms`, error và các field chuẩn bị cho thí nghiệm
Prompt Injection. Chạy acceptance test:

```bash
python scripts_test_phase8.py
```

Để kiểm tra trace 5 bước bằng Agent thật:

```bash
python scripts_test_phase8.py --full-flow
```

`--full-flow` sẽ gửi retrieved context từ Knowledge Base tới LLM provider đã
cấu hình. File trace cũng chứa prompt và nội dung Agent xử lý, vì vậy không nên
commit hoặc chia sẻ `tracing/logs/`.

## 12. Security testbed và defense mode

Chọn chế độ qua `.env`:

```env
DEFENSE_MODE=off
```

hoặc:

```env
DEFENSE_MODE=on
```

Ở mode `off`, Input/Retrieval/Output Guard là pass-through. Ở mode `on`, hệ
thống chặn heuristic Direct Prompt Injection, lọc retrieval theo trust level,
content hash và injection pattern, đồng thời redaction secret trong final output.
Tool allowlist của Executor luôn được áp dụng ở cả hai mode.

Input/Retrieval Guard chuẩn hóa Unicode và nhận diện các mẫu injection phổ biến
bằng tiếng Anh, tiếng Việt, Tây Ban Nha, Pháp, Đức, Bồ Đào Nha, Nga, Trung,
Nhật và Hàn. Đây vẫn là lớp heuristic: dùng để chặn sớm các mẫu rõ ràng, không
thay thế bộ phân loại ngữ nghĩa hoặc mô hình kiểm duyệt chuyên dụng.

Chạy so sánh không cần API:

```bash
python scripts_test_phase9.py
```

Seed case cho Prompt Injection nằm tại
`experiments/prompt_injection/cases.jsonl`. Nhãn ground truth poisoning không
được chuyển cho Agent khi retrieval.
