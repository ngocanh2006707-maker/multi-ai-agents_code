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
  - Local embedding bằng `BAAI/bge-m3`
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

Sau đó cài thêm dependency cho local embedding:

```bash
pip install langchain-huggingface sentence-transformers
```

Mở `.env`, điền API key Google AI Studio cho LLM và cấu hình BGE-M3 cho
embedding:

```env
MODEL_PROVIDER=google
MODEL_NAME=gemini-3.1-flash-lite
API_KEY=YOUR_GOOGLE_AI_API_KEY

EMBEDDING_PROVIDER=local
EMBEDDING_MODEL=BAAI/bge-m3
```

Sau khi BGE-M3 đã được tải đầy đủ vào cache, có thể tắt hoàn toàn việc kiểm tra
Hugging Face Hub và các dòng retry do kết nối bằng:

```env
EMBEDDING_LOCAL_FILES_ONLY=true
```

Ở chế độ này project tự bật Hugging Face offline mode, ẩn progress bar và chỉ
đọc model trong cache. Nếu cache chưa đầy đủ, đặt lại thành `false`, chạy một lần
khi có mạng để tải model, rồi mới bật lại.

`API_KEY` chỉ dùng cho LLM. BGE-M3 chạy local và không dùng Gemini embedding
quota. Lần đầu load model, `sentence-transformers` sẽ tự tải trọng số BGE-M3 về
cache của máy; không commit trọng số model vào repository.

## 2. Test riêng Phase 3

```bash
python scripts_test_phase3.py
```

Script này chỉ kiểm tra Planner phân route và plan. Worker vẫn được giả lập
cố ý để test Phase 3 độc lập.

## 3. Knowledge Base Phase 4

Nguồn KB hiện tại đã được chuẩn hóa và gộp tại:

```text
data/raw/combined_documents.jsonl
```

File này gồm 15 document: 6 seed baseline và 9 tài liệu nghiên cứu. Với cấu
hình mặc định `chunk_size=900`, `overlap=120`, ingestion tạo 652 chunk.

Project vẫn giữ file seed nhỏ để kiểm thử pipeline độc lập:

```text
data/raw/seed_documents.jsonl
```

Đây chỉ là **seed data cho baseline**. Khi build KB đầy đủ, luôn dùng
`combined_documents.jsonl` để không làm mất các tài liệu đã gộp.

Chroma lưu vector tại `data/vector_db/`. Vector tài liệu có thể được chia sẻ dưới
dạng snapshot, nhưng mỗi máy vẫn cần BGE-M3 để tạo embedding cho câu hỏi mới.
Không dùng Gemini hoặc embedding model khác để truy vấn snapshot BGE-M3 vì các
model không cùng không gian vector.

Trước khi build toàn bộ KB, test model bằng một query nhỏ:

```bash
python -c "from dotenv import load_dotenv; load_dotenv(); from knowledge_base.embeddings import embed_query; v=embed_query('Kiểm tra prompt injection'); print('dimension:', len(v))"
```

Với BGE-M3, kết quả mong đợi là vector 1024 chiều. Sau khi test thành công,
build/index toàn bộ KB:

```bash
python scripts_build_kb.py --input data/raw/combined_documents.jsonl --chunk-size 900 --overlap 120 --reset
```

`--reset` xóa collection hiện tại trước khi ghi index mới. Chỉ dùng tùy chọn này
khi file đầu vào chứa toàn bộ KB cần giữ hoặc khi đổi embedding model. Không trộn
vector BGE-M3 với vector Gemini trong cùng collection.

Pipeline đang chạy:

```text
JSONL Document
    ↓ Validation + cleaning
Normalized Document
    ↓ chunk_size=900, overlap=120
652 Chunks
    ↓ BAAI/bge-m3 chạy local
1024-dimensional Vectors
    ↓ Chroma upsert
data/vector_db/
```

Chunking chia tài liệu dài thành các đoạn nhỏ có phần chồng lấn để không mất ngữ
cảnh tại ranh giới. Embedding biến từng chunk thành vector số; retrieval biến câu
hỏi bằng cùng model rồi tìm các vector gần nhất theo cosine similarity.

Kiểm tra số vector sau khi build:

```bash
python -c "from dotenv import load_dotenv; load_dotenv(); from knowledge_base.vector_store import collection_count; print('Số vector:', collection_count())"
```

Kết quả mong đợi:

```text
Số vector: 652
```

Thử semantic retrieval:

```bash
python -c "from dotenv import load_dotenv; load_dotenv(); from knowledge_base.retrieval import search; import pprint; pprint.pp(search('Cách phòng chống prompt injection', top_k=3))"
```

Chỉ build một file khác khi chủ động tạo collection mới hoặc thay toàn bộ nguồn
dữ liệu:

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

### Trust do hệ thống quản lý và source quarantine

Ở `DEFENSE_MODE=off`, `trust_level` trong JSONL được giữ nguyên và retrieval
xếp hạng thuần theo semantic similarity. Đây là baseline ít phòng thủ, vì tài
liệu có thể tự khai trust cao và hệ thống không dùng trust để hạ hạng.

Ở `DEFENSE_MODE=on`, `trust_level` trong JSONL chỉ được lưu ở
`claimed_trust_level` để audit. Giá trị dùng cho reranking/guard được hệ thống
gán theo `configs/source_trust.yaml`; nguồn không có trong registry nhận trust
mặc định `0.0` nên không thể tự nâng trust bằng cách sửa JSONL.

Mỗi source trong registry có thêm cờ `allowed`. Khi build với
`DEFENSE_MODE=off`, nguồn chưa được phép vẫn đi qua để tạo baseline. Khi build
với `DEFENSE_MODE=on`, nguồn đó không được embedding/upsert vào collection
chính và được ghi vào `artifacts/quarantine/*.jsonl`. Có thể chọn đường dẫn:

```powershell
$env:DEFENSE_MODE = "on"
python scripts_build_kb.py --input data/raw/combined_documents.jsonl `
  --quarantine-output artifacts/quarantine/review.jsonl --reset
```

Retrieval Guard chỉ kiểm tra `trust_managed` và `source_allowlisted` ở On và sẽ
lọc chunk thiếu metadata an toàn. Off bỏ qua hai tín hiệu này. Vì snapshot KB cũ
không có hai field này, cần rebuild collection trước khi chạy On; nếu chưa
rebuild, On sẽ fail-closed và lọc các chunk cũ.

### Chia sẻ vector database

`data/vector_db/` chứa SQLite và các file index nhị phân. Không sao chép thư mục
này trong lúc ứng dụng hoặc tiến trình build đang ghi dữ liệu. Với coursework
nhỏ có thể commit snapshot, nhưng GitHub Release hoặc Git LFS phù hợp hơn Git
thường vì các file nhị phân thay đổi toàn khối.

Người nhận snapshot không cần embedding lại tài liệu, nhưng vẫn phải:

1. Cài `langchain-huggingface` và `sentence-transformers`.
2. Cấu hình `EMBEDDING_PROVIDER=local` và `EMBEDDING_MODEL=BAAI/bge-m3`.
3. Tải BGE-M3 ở lần truy vấn đầu tiên để embedding câu hỏi.
4. Dùng phiên bản Chroma tương thích với phiên bản đã tạo snapshot.

Nên phát hành cùng snapshot các file sau:

```text
data/raw/combined_documents.jsonl  # nguồn có thể rebuild
data/vector_db/                    # snapshot đã embedding
.env.example                       # cấu hình không chứa secret
requirements.txt                   # dependency được pin khi release
```

Nếu thay model hoặc revision model, phải rebuild toàn bộ collection. Tên model,
provider và dimension được lưu làm embedding fingerprint để ngăn trộn vector
không tương thích.

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

Với các route có Research, câu trả lời cuối hiển thị thêm mục Top-K theo đúng
thứ tự sau rerank và Retrieval Guard. Mỗi mục gồm tiêu đề, nguồn, similarity,
trust và trích đoạn tối đa 280 ký tự. Tiêu đề/nội dung chỉ dùng để hiển thị;
không được xử lý như chỉ dẫn hệ thống. Số kết quả thực tế có thể nhỏ hơn K nếu
không đủ kết quả đạt ngưỡng hoặc có chunk bị Retrieval Guard lọc.

Các field thử nghiệm `is_poisoned`, `attack_type`, `experiment_id` vẫn được
lưu trong vector database để đánh giá sau này, nhưng **không trả cho Research
Agent**, tránh lộ ground truth trong thí nghiệm poisoning.

## 6. File quan trọng đã triển khai trong Phase 4

```text
knowledge_base/
├── ingestion.py       # validate, clean, đọc JSONL
├── chunking.py        # chia chunk + content hash
├── embeddings.py      # BGE-M3 local hoặc Google embedding theo cấu hình
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

Ở mode `off`, hệ thống dùng baseline gần như không phòng thủ: guard là
pass-through, không kiểm tra trust/hash/source, không trust-aware reranking,
không gắn retrieved context là dữ liệu không tin cậy và không chặn luồng thực
thi vì confidence thấp. Detector injection/secret vẫn có thể ghi telemetry
nhưng không thay đổi input, retrieval hay output.

Ở mode `on`, hệ thống chặn heuristic Direct Prompt Injection, quarantine nguồn
chưa duyệt khi build, lọc retrieval theo trust level/content hash/injection
pattern, trust-aware reranking, hardening prompt của Analyst, confidence gate
trước Executor và redaction secret trong final output.

Các giới hạn schema, timeout/process isolation và tool allowlist của Executor
luôn được áp dụng ở cả hai mode. Đây là ranh giới vận hành tối thiểu để testbed
không gọi shell/network/delete/secret ngoài phạm vi, không phải defense biến đổi
trong thí nghiệm OFF/ON.

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
