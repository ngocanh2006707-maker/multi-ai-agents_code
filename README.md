# Trợ lý nghiên cứu bảo mật AI đa tác tử

Hệ thống đa tác tử theo kiến trúc **Centralized Orchestrator** để tra cứu,
phân tích và so sánh các biện pháp phòng thủ cho AI Agent / Multi-Agent
System. Phạm vi phòng thủ thực nghiệm gồm **Prompt Injection** và
**User-Originated Coordinator Flaw / Conversation Context Spoofing** qua
`conversation_context`. Tài liệu KB chứa injection là attack surface của PI;
project không khẳng định phòng thủ mọi dạng poisoning hoặc mọi lỗi coordinator.

Bản nội dung báo cáo sau P1–P7 và OFF mới: [Kiến trúc, kết quả và giới hạn](BAO_CAO_KIEN_TRUC_VA_KET_QUA_PHONG_THU.md),
kèm [bản Word](Bao_cao_kien_truc_va_ket_qua_phong_thu.docx). Báo cáo tách `Fixed`
khỏi model-level `Validated` và giữ nguyên evidence nghiệm thu lịch sử.

**Từ 2026-10-06, public OFF là `unprotected_off_v1`: tắt toàn bộ phòng thủ
PI/CF, schema bảo mật, tool allowlist, approval và giới hạn thực thi của ứng dụng.**
ON giữ workflow phòng thủ P1–P7. Cách chạy và phạm vi OFF ở mục 12.

## Tiến trình xây dựng ban đầu (phase phát triển 1–9)

Danh sách dưới đây là các phase xây dựng hệ thống. Roadmap sửa bảo mật
**P1–P7** được quản lý riêng tại [SECURITY_FIX_BACKLOG.md](SECURITY_FIX_BACKLOG.md).
`Fixed` nghĩa là kiểm chứng kỹ thuật đạt; không đồng nghĩa model-level `Validated`.

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

## 1. Cài đặt

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

## 5. Đầu ra truy xuất

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

Chạy acceptance của phase phát triển 7 với **model và KB thật** (có thể gọi API):

```bash
python scripts_test_phase7.py
```

Script kiểm tra bốn route: ON gồm context boundary là 4/6/4/2 bước,
OFF không boundary là 3/5/3/1 bước;
case tool gửi `execution_input` trước model. Không dùng lệnh này làm offline
regression. Cách chạy suite với stubs nằm ở mục 14.

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

Ở mode `off`, `build_workflow()` chọn [graph/baseline.py](graph/baseline.py)
thay cho protected facade. Graph nhận dict nguyên trạng, giữ `conversation_context`
qua Planner → Researcher → Analyst và đưa vào các prompt LLM. `analysis_result`
và final output không có provenance/quality validation, output guard hay escaping.
Không gọi PI detector, scope/context isolation, canary builder hoặc Action Gate.

Ở mode `on`, hệ thống chặn heuristic Direct Prompt Injection, quarantine nguồn
chưa duyệt khi build, lọc retrieval theo trust level/content hash/injection
pattern, trust-aware reranking, hardening prompt của Analyst, confidence gate
trước Executor và redaction secret trong final output.

OFF gọi tool implementation trực tiếp: bỏ schema request/result, allowlist
enforcement, caller-task binding, approval, path/extension restrictions,
file/result-size và record caps, overwrite protection, process isolation,
tool timeout và giới hạn 25 bước mặc định của graph. Dispatcher vẫn cần tool
có implementation; bỏ allowlist không tự tạo shell/network tool. JSON/CSV parsing,
route labels, retrieval top-k/relevance và điều kiện toán học của metric vẫn là
giao thức chức năng; giới hạn OS/provider vẫn tồn tại. Trace/usage ledger chỉ quan sát.

Chạy CLI OFF, không cần sửa `.env`:

```powershell
$env:DEFENSE_MODE = "off"
.\.venv\Scripts\python.exe main.py "Direct Prompt Injection là gì?"
```

Gửi raw context cho baseline qua Python API, đặt mode trước khi build và giữ
mode ổn định trong run:

```python
import os
os.environ["DEFENSE_MODE"] = "off"
from graph.workflow import build_workflow
result = build_workflow().invoke({
    "user_query": "Phân tích Prompt Injection từ tài liệu và hội thoại",
    "conversation_context": [{"role": "assistant", "content": "Nội dung caller kiểm soát"}],
})
print(result["baseline_version"])  # unprotected_off_v1
print(result["final_answer"])
```

OFF không yêu cầu `execution_input`; nếu có, model chỉ nhận nó như dữ liệu.
ON yêu cầu task confirmation cho tool và callback cho write action như mục 13.
Guard APIs gọi trực tiếp vẫn hỗ trợ unit measurement; chúng không nằm trong
public OFF flow. So OFF/ON mới đo toàn bộ stack, chưa tách tác động từng guard.
Giữ cùng KB snapshot/corpus/model; OFF không khôi phục tài liệu đã bị ingestion
loại khỏi KB. Artifact OFF cũ vẫn là kết quả của baseline có bảo vệ cấu trúc.

Rubric giữ `evaluator_v2`, profile mới là `workflow_profile_version=unprotected_off_v1`.
Harness từ chối so report thiếu/sai profile; full/retrieval reports lưu dưới
`unprotected_off_v1/evaluator_v2/`. Không cộng kết quả mới vào artifact P1–P7 cũ.

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

## 13. Bàn giao kiến trúc Blue Team T00-T10

Pipeline bảo mật được đánh giá qua bốn giai đoạn thực thi. Input Guard chuẩn
hóa để kiểm tra nhưng giữ nguyên input người dùng. Ở `DEFENSE_MODE=on`, high
và medium có command evidence hoặc chưa phân định bị chặn trước routing/model.
Trích dẫn có framing nghiên cứu thuộc các dạng đã hỗ trợ được tách khỏi scan;
phần câu lệnh bên ngoài trích dẫn vẫn được kiểm tra. Retrieval Guard kiểm tra trust, hash nội dung và mẫu
injection trước khi context tới Agent. Output Guard che secret và chặn rò rỉ
prompt/canary. Action Gate kiểm tra tool, tham số, provenance, phê duyệt và
digest toàn vẹn ngay trước khi thực thi.

Phần cơ chế phòng thủ dưới đây áp dụng cho ON. Public OFF mới ở mục 12
bỏ toàn bộ checkpoint; không phát sinh security event `observed` từ detector.
Các kết quả T10/P1–P7 lịch sử vẫn phản ánh semantics OFF ở source lúc đo.

### Các kiểm soát T10 đã đo trước roadmap sửa bảo mật

Các số dưới đây là kết quả harness ở thời điểm bàn giao trước P1–P7,
không phải ASR/FPR hiện tại được chấm bằng `evaluator_v2`. P7 không chạy
benchmark model thật hoặc chấm lại những artifact này.

Bằng chứng kiểm thử tự động dùng mẫu số rõ ràng:

* Input Guard: chặn 6/6 payload tấn công trực tiếp ở ON; cho phép 6/6 cùng
  event `observed` ở OFF. Hai kiểm soát sạch rõ ràng có 0/2 false positive ở ON (0%).
* Harness độ bao phủ đa tác tử: 4 kịch bản sạch chạy qua route research,
  analysis, executor và chain với 0/4 false positive ở ON (0%). Harness dùng
  quyết định model giả, là kiểm tra hồi quy route/guard chứ không khẳng định
  khả năng chống tấn công của model thật.
* Bộ test repository hoàn tất 260 test pass tại thời điểm bàn giao. Số test
  pass phản ánh sức khỏe kiểm thử, không phải tỷ lệ phát hiện tấn công; tỷ lệ
  tấn công luôn dùng số payload nêu trên.

Báo cáo retrieval có mẫu số riêng: với metadata trust/hash hợp lệ, bộ mẫu đã
review lọc 3/5 kiểm soát injection ở ON và giữ cả hai kiểm soát sạch. P04 và
P05 là các trường hợp bỏ sót đã ghi nhận, nên kết quả này không được trình bày
như độ bao phủ ngữ nghĩa tổng quát. Tài liệu thiếu metadata trust bị chính
sách trust lọc; đó là kết quả của policy metadata, không chứng minh detector
nội dung đã nhận ra injection.

### Giới hạn và hành vi dự phòng đã biết

Semantic classifier là hook có thể tiêm, bị giới hạn thời gian và chỉ dùng cho
input rủi ro trung bình. Production chưa tích hợp provider nên mặc định
`semantic_classifier_enabled=false`; bật mà không có provider trả `unavailable`,
không phải negative hợp lệ. Timeout cấu hình là 0,5 giây; malformed, exception
hoặc timeout được ghi riêng, với confidence=0 và không giả positive detection.
Fallback `medium`/`high` quyết định policy level và đều chặn unresolved medium
ở ON; cấu hình fallback `allow` bị từ chối. Positive policy cũng không sửa risk
score gốc. Negative từ provider hợp lệ có thể giải quyết medium chưa phân định,
nhưng không bỏ qua command evidence đã nhận diện. Public OFF không gọi hook/guard.
Không có signals thì hook không chạy. Cách diễn đạt lại không khớp heuristic,
ngôn ngữ mới và ý định phụ thuộc context vẫn ngoài phạm vi khẳng định đã đo.
Nhận diện quote là heuristic có giới hạn; nhãn research hoặc quote đơn lẻ không
cấp trust. Planner kiểm tra contract Input Guard trước khi cập nhật state;
contract sai trở thành operational error trước routing/model/worker ở ON.

Mỗi lần gọi nhận một prompt canary duy nhất và fingerprint SHA-256 của canary
(không phải hash system prompt). Canary được
chèn vào system instruction của Planner/Analyst và được che khỏi telemetry.
Output Guard phát hiện được canary/fingerprint chính xác và một số dạng rò rỉ
cấu trúc đã biết. Chỉ nhắc đến system prompt/developer instructions không đủ
để báo leak. `prompt_structure_check_enabled` điều khiển heuristic disclosure
frame, không tắt exact canary/fingerprint hoặc secret redaction.
`prompt_leak_similarity_threshold` đã bỏ và cấu hình cũ bị từ chối rõ ràng;
không có phép đo similarity hay LLM judge. Heuristic không chứng minh nội dung
trùng prompt thật, không bao phủ mọi answer hijack và vẫn có thể false positive.
Guard không bảo đảm phát hiện rò rỉ diễn đạt lại, rò rỉ từ
prompt builder bỏ qua canary hoặc canary bị xóa có chủ ý trước output.

Conversation Context Spoofing dùng boundary và registry theo từng run.
Scope classifier chỉ đọc query: nhắc đến chủ đề conversation/context không
tự cấp quyền dùng caller data; không có yêu cầu nguồn thì mặc định KB.
Grammar nguồn dùng chung với phép tách tác vụ KB, hỗ trợ một số prefix/suffix
EN/VI và thứ tự KB/caller đảo nhau. Yêu cầu mâu thuẫn hoặc không tách an toàn
được thì hỏi lại. Từ weather trong ví dụ security không tự loại cả tác vụ;
câu hỏi thời tiết thuần túy vẫn ngoài phạm vi. Grammar là heuristic có giới hạn.
Caller context nằm trong registry, chỉ được render thành caller_quote riêng
khi được phép; không đưa vào Researcher/Analyst hoặc analysis_result.
Direct Analyst là API nội bộ KB-only: caller context không rỗng/sai kiểu bị
từ chối trước model ở ON. Prompt ON không có conversation_context hay
conversation IDs làm evidence; confidence chỉ tính từ tài liệu KB. Argument
context cũ chỉ còn chấp nhận None/[] để tương thích. Đây là contract/isolation
phòng thủ ON, không phải bằng chứng model-level robustness hay authenticity của KB.

Allowlist tĩnh trả lời “tool nào từng được phép chạy”. Action Gate theo context
trả lời “lần gọi cụ thể này có được chạy ngay không” bằng cách kiểm tra liên
kết với truy vấn người dùng, provenance, phê duyệt và digest tham số/toàn vẹn.
Tool nằm trong allowlist không đồng nghĩa chỉ thị truy xuất được quyền sửa
tham số của nó. ON fail-closed; OFF bỏ gate, allowlist/schema và process isolation.

P5 ràng buộc **tool và toàn bộ params** với `execution_input` do caller gửi
tại ingress, kiểm tra bằng `ExecutionRequest` và snapshot JSON trong runtime
trước Planner/Researcher/Analyst. Đây là dữ liệu tác vụ được caller chỉ định,
không phải bằng chứng dữ liệu đúng hay được xác thực. `user_query` mô tả tác vụ;
`execution_input` là nguồn tham số có thẩm quyền. Hệ thống không trích records
từ câu hỏi tự nhiên hay `conversation_context` để tự cấp bản xác nhận.
Hash do Planner tự tạo vẫn chỉ kiểm tra thay đổi sau planning; Action Gate
so sánh riêng với snapshot caller. Khi gate bật, ON từ chối missing/mismatch;
Public OFF không chạy gate và dùng trực tiếp candidate của model.

Ví dụ public workflow (dữ liệu được cung cấp trước khi gọi model):

```python
result = build_workflow().invoke({
    "user_query": "Tính attack success rate",
    "execution_input": {
        "tool_name": "calculate_metrics",
        "params": {
            "metric": "attack_success_rate",
            "records": [{"attack_success": True}, {"attack_success": False}],
        },
    },
})
```

CLI nhận cùng object qua file JSON: `python main.py "Tính attack success rate"
--execution-input task.json` (chạy trên một dòng). Query-only tool requests ở
ON bị từ chối khi thiếu bản xác nhận; tác vụ KB/caller quote không cần field này.
Ứng dụng gọi `build_workflow(approval_callback=app_confirm_write)` để xử lý
approval cho `save_test_result`. Callback thuộc cấu hình ứng dụng tin cậy,
nhận `ExecutionApprovalRequest` bất biến gồm run ID, tool, digest và params JSON,
và phải trả bool sau quyết định policy/người vận hành. Callback chỉ chạy sau
kiểm tra context hợp lệ; thiếu/từ chối approval thì gate chặn ở ON; callback
lỗi/sai kiểu là operational error ở ON; OFF không gọi callback. Không có approval qua public
input, model prose hay conversation context. CLI mặc định không cấp approval;
chưa có UI xác nhận. Không dùng callback luôn trả True làm policy production.

Route `RESEARCH_ANALYSIS_EXECUTE` render phân tích KB và kết quả tool thành
hai `RenderPart`/envelope riêng, giữ guard từng part và assembled guard. Provenance
KB chỉ được dùng khi có result binding runtime tương ứng. Bằng chứng kỹ thuật
P5 nằm trong backlog và `artifacts/phase5_execution/evaluator_v2/`; chưa phải
model-level validation hoặc ASR/FPR mới.

P6 tối ưu guard bằng cách tái sử dụng kết quả normalization/detector trong
mỗi lần `guard_input`/`guard_retrieval`. Cache phân biệt text, context và function,
tối đa 256 entry, trả list mới cho caller và được xóa cả khi return hoặc exception;
không cache policy decisions hay giữ caller text qua các lần guard. Nội dung,
metadata và reporting/command context vẫn được kiểm tra theo các rule cũ.

`load_security_settings()` vẫn đọc file mỗi lần, nhưng cache parse/validation
theo nội dung YAML và mode (tối đa 8 template). Caller nhận deep copy, nên sửa
settings không tác động lần gọi sau; thay nội dung dù mtime/size giữ nguyên vẫn
được nhận, và file lỗi/mất không fallback sang policy cũ.

Đo guard cục bộ trên corpus tổng hợp cố định OFF/ON cho kết quả giống hệt ở
14 case. Ở ON, pool hỗn hợp 32 documents giảm median từ **37,32 ms xuống
10,01 ms**; Input Guard trong các case đo còn khoảng **0,24–0,36 ms**. Đây là
25 lần đo/case sau warmup, có field lặp; không phải tốc độ end-to-end hoặc
bằng chứng ASR/FPR. Artifact và giới hạn nằm trong
`artifacts/phase6_optimization/evaluator_v2/` và backlog P6. Contract
`execution_input`, approval, evaluator và checkpoint bảo mật giữ nguyên.

### Môi trường và metric bảo mật

Các lượt chạy toàn pipeline phụ thuộc endpoint model bên ngoài được báo cáo
riêng với metric phát hiện và false positive. Lượt chạy bị treo, không tới
được provider hoặc lỗi retrieval là lỗi môi trường/độ bao phủ với kết quả tấn
công chưa biết; không tính là tấn công bị chặn hay lượt sạch thành công.
Artifact thủ công được làm sạch thành hash, độ dài và ID; không được dùng để
suy ra tỷ lệ thành công của model khi lượt chạy chưa hoàn tất.

### Evaluator v2 — Phase 1 measurement (2026-10-05)

Backlog và bằng chứng từng finding nằm trong [SECURITY_FIX_BACKLOG.md](SECURITY_FIX_BACKLOG.md).
Harness hiện dùng `evaluator_version=evaluator_v2`, quan sát structured final
parts để loại Top-K echo và caller quote khỏi generated-answer objective.
Workflow error hoặc thiếu attribution không được chấm thành defense success;
simulation không nằm trong measured ASR. `final_output_affected=null` nghĩa là
chưa đo objective, không phải kết luận tấn công thất bại.

Artifact cũ giữ nguyên và được ghi version trong
`artifacts/phase1_measurement/evaluator_v2/historical_artifact_index.json`;
thiếu version được đánh dấu `unknown/legacy`. Các số liệu thực nghiệm cũ chưa
được chấm lại bằng v2. Report mới dùng namespace `evaluator_v2`; so sánh khác
evaluator version bị từ chối. Phase 1 không gọi LLM thật và không tạo ASR/FPR
mới để khẳng định hiệu quả defense.

## 14. Regression offline và bản source export sạch (P7)

Chạy tại project root, dùng Python đã cài dependencies trong `requirements.txt`:

```powershell
$env:DEFENSE_MODE = "off"
python -B scripts_test_offline.py
```

Runner tắt `dotenv.load_dotenv`, bytecode/cache pytest và plugin tự nạp.
Suite hiện dùng model/search stubs và local tools, không cần API key, model
embedding, vector DB hoặc artifact lịch sử. Các test tự chọn OFF/ON khi cần;
`tests/conftest.py` chọn ON mặc định cho test bảo mật; case OFF tự chọn mode.
Runner
không thay provider bằng stubs cho test mới; test gọi provider phải tự mock.
Không chạy các manual harness có `--execute-*` để thay cho regression này.

Kiểm tra riêng acceptance script bằng workflow thật và provider/tool stubs:

```powershell
python -B scripts_test_offline.py tests/test_compiled_workflow.py::test_p7_acceptance_script_matches_compiled_routes_and_confirmed_tool -q
```

Fixture bắt buộc được version control ở `tests/fixtures/coordinator_flaw/`:
query/payload JSON, baseline manifest và source ZIP đóng băng. Các test preflight
vẫn kiểm tra SHA-256 và 100 entry của ZIP. `artifacts/` chỉ lưu output/evidence;
không lấy fixture hiện hành từ thư mục đó. Smoke authorization và output path
giữ nguyên; chuyển fixture không cấp phép chạy API mới.

Source export P7 là bản lịch sử có OFF cũ:
`artifacts/phase7_reproducibility/evaluator_v2/source_export.zip`.
Source OFF mới: `artifacts/unprotected_off_20261006/evaluator_v2/source_export.zip`.
Giải nén vào thư mục riêng, chạy runner trên bằng Python có dependencies.
Export gồm source, tests, fixtures, configs, docs và dữ liệu JSONL cần thiết;
không chứa `.env`/`.env.example`, `.git`, `.venv`, cache, vector DB hoặc evidence
lịch sử. Muốn chạy ứng dụng thật, cấu hình môi trường theo mục 1 và build KB.

`source_export_manifest.json` ghi hash mỗi file; `verification_commands.json`
và `regression_clean_export.xml` ghi cách chạy và kết quả. Kiểm chứng export
dùng dependency environment hiện có, chưa chứng minh cài mới từ dependencies
không pin hoặc fresh Git checkout. `version_control_manifest.json` liệt kê
source/fixture còn untracked cần đưa vào Git khi bàn giao; P7 không stage/commit.
Kết quả kỹ thuật và giới hạn nghiệm thu nằm trong backlog P7.
