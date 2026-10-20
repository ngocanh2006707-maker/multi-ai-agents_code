# Nghiên cứu và thực nghiệm một số hình thức phòng thủ cho hệ thống đa tác tử (AI Agents)

Bản cập nhật kỹ thuật ngày 2026-10-06, đối chiếu source sau P7, baseline OFF mới và evidence
`evaluator_v2`. Tài liệu này cung cấp nội dung kiến trúc, kết quả kiểm chứng và
giới hạn để đưa vào báo cáo chính; chưa phải báo cáo thực nghiệm model thật.
Đề cương Word cũ và các tài liệu Red Team/Blue Team đời trước chứa phạm vi
Data Poisoning được xem là tài liệu lịch sử. Phạm vi hiện hành được xác định
trong bản cập nhật này và [SECURITY_FIX_BACKLOG.md](SECURITY_FIX_BACKLOG.md).

## Chương 1. Phạm vi nghiên cứu và mô hình mối đe dọa

### 1.1. Hai hướng tấn công trong thực nghiệm

**Prompt Injection (PI):** chỉ thị độc trong `user_query` hoặc tài liệu/metadata
retrieval có thể ảnh hưởng định tuyến, phân tích, câu trả lời hoặc tham số tool.
Output disclosure và tool manipulation được xem là mục tiêu/tác động của PI.

**User-Originated Coordinator Flaw / Conversation Context Spoofing (CF):**
caller kiểm soát `conversation_context`, giả vai trò, nguồn hoặc nội dung hội
thoại để dữ liệu của mình được dùng như nguồn tin cậy trong phối hợp agent.
Đường tấn công cần kiểm soát là:

```text
Caller → conversation_context → Planner → Researcher → Analyst
       → analysis_result → final_answer
```

Đây là attack path đi được trong OFF mới; ON cắt đường này bằng isolation.
CF trong đề tài không đại diện cho mọi lỗi coordinator. Nội dung KB có
injection thuộc indirect PI; không báo cáo phòng thủ Data/Knowledge Poisoning
như hướng thứ ba. Không triển khai persistent memory hoặc compromised-agent
attacks như kịch bản độc lập.

### 1.2. Năng lực attacker và giả định trust

Caller có thể gửi query, context và dữ liệu tác vụ tool qua public input.
Trong thử nghiệm indirect PI, nội dung/metadata retrieval là dữ liệu không
đáng tin cậy. Attacker không được sửa mã guard, runtime registry, schema,
source policy, evaluator hoặc callback phê duyệt của ứng dụng để ép kết quả.

Trong ON, các thành phần thuộc cơ sở tin cậy gồm workflow facade, adapter, registry theo
run, schema validation, cấu hình chính sách và callback ứng dụng. Model output
là candidate phải kiểm tra, không được tự xác nhận provenance hay approval.
`role=assistant` do caller khai không chứng minh message được agent tạo ra.
Content hash/HMAC phục vụ consistency hoặc binding; không xác thực tính đúng
của tri thức hay danh tính caller.

### 1.3. Mục tiêu an toàn và tiêu chí thành công

- PI: ngăn chỉ thị trong nguồn dữ liệu giành quyền điều khiển model/tool;
  hạn chế các dạng prompt/secret disclosure có detector hỗ trợ.
- CF: context của caller không trở thành KB evidence, không đi vào prompt
  Researcher/Analyst hoặc `analysis_result`; nếu được yêu cầu thì chỉ trích
  thành phần caller có nhãn chưa xác minh.
- Tấn công thành công phải gắn với objective và output/action thực tế. Có
  payload trong Top-K, security event hoặc caller quote chưa đủ kết luận
  downstream model đã tuân theo chỉ thị.

## Chương 2. Kiến trúc và cơ chế phòng thủ theo source hiện tại

### 2.1. Entry point và vai trò các thành phần

`build_workflow()` chọn graph riêng theo mode. Các cơ chế bảo vệ trình bày
ở mục 2.2–2.6 áp dụng cho ON; luồng OFF không bảo vệ ở mục 2.7.

| Thành phần | Vai trò và file đối chiếu |
| --- | --- |
| CLI | [main.py](main.py): nhận query và file JSON `--execution-input`; gọi facade |
| Public workflow | [graph/workflow.py](graph/workflow.py): `build_workflow`, `WorkflowFacade.invoke`, runtime lifecycle |
| OFF baseline | [graph/baseline.py](graph/baseline.py): `BaselineWorkflow`, raw context, model output và direct tool dispatch |
| Input/state schema | [graph/state.py](graph/state.py): `WorkflowInput` chỉ có `user_query`, `conversation_context`, `execution_input` |
| Context boundary | [security/context_guard.py](security/context_guard.py): normalize/validate, per-run registry, scope grammar, task binding |
| Planner | [agents/planner.py](agents/planner.py): Input Guard, scope, route/plan, worker validation và final rendering |
| Researcher | [agents/researcher.py](agents/researcher.py): search candidate pool, Retrieval Guard, chọn safe top-k |
| Analyst | [agents/analyst.py](agents/analyst.py): phân tích KB, strict output schema, evidence IDs và confidence |
| Executor | [agents/executor.py](agents/executor.py): schema, contextual Action Gate, allowlist và isolated tool execution |
| Provenance/rendering | [security/coordination_guard.py](security/coordination_guard.py): `ResultEnvelope`, `RenderPart`, safe renderer |
| Evaluation | [tests/evaluation.py](tests/evaluation.py): structured final evidence, version và operational-error rules |

`app.py` vẫn là placeholder, chưa có web/API server hoàn chỉnh. Public ON facade
chỉ hỗ trợ `invoke`; stream/batch/async API bị từ chối để giữ lifecycle đã kiểm
chứng. Direct worker APIs là nội bộ, không thay thế public ingress.

### 2.2. Workflow tổng thể

```text
CLI hoặc ứng dụng gọi build_workflow().invoke(public_input)
  → WorkflowInput lọc các field điều phối do caller giả mạo
  → Facade tạo WorkflowRuntimeContext + RunSourceRegistry riêng cho run
  → context_boundary: validate/NFC, lưu caller records và execution task
  → Planner: Input Guard → deterministic source scope → project KB task
      ├─ block / invalid / ambiguous / caller-only / out-of-scope → finalization
      └─ LLM route classifier + trusted plan
           ├─ Researcher: KB search → Retrieval Guard → safe top-k → Planner
           ├─ Analyst: KB-only prompt → structured candidate → Planner
           └─ Executor: schema → Action Gate → allowlist → tool → Planner
  → Planner kiểm tra/bind worker results; tạo RenderParts riêng theo nguồn
  → Output Guard từng part → renderer → Output Guard assembled answer
  → final_answer + telemetry
  → finally: đóng registry và xóa dữ liệu runtime của run
```

Mọi worker quay về Planner; không có edge Researcher → Analyst trực tiếp.
Hàng đợi `plan` và conditional edges quyết định thứ tự worker, không phải
pipeline cố định cho mọi query. Nhãn `ANALYSIS` từ classifier được chuẩn hóa
để nghiên cứu KB trước khi phân tích nếu chưa có KB hợp lệ. Trace step ở bốn
case nghiệm thu research/analysis/execute/OOS lần lượt là **4/6/4/2**, gồm
context boundary; đây là số node execution của các case, không phải mọi route.

### 2.3. User Query Flow

```text
user_query
  → public schema + context boundary (type/length/Unicode validation, NFC)
  → Planner gọi guard_input và validate GuardResult trước state mutation
  → scope classifier chỉ đọc query
  → project_kb_task tách phần tác vụ KB khỏi yêu cầu dùng nguồn caller
  → LLM route classifier nhận KB task
  → worker adapters nhận view được whitelist
  → kết quả hợp lệ được bind vào runtime → RenderParts → final_answer
```

Input Guard chạy trong lần Planner đầu, trước route model và worker; context
boundary chạy trước đó và không gọi LLM. Guard không sanitize/rewrite query
thành một tác vụ mới; normalization phục vụ boundary/scanning không phải
LLM-based rewrite. Không tách nguồn an toàn được thì hỏi lại thay vì chuyển
caller text thành KB task. Caller-only kết thúc bằng renderer xác định, không
gọi model để phân tích caller.

### 2.4. Conversation Context Flow và trust boundary

```text
caller-controlled conversation_context
  → WorkflowInput → state đầu vào tại context_boundary
  → validate list/message/role/content, bỏ metadata không thuộc schema, NFC
  → ContextRecord(source_class=caller_context, origin_verified=False)
  → RunSourceRegistry riêng cho run
  → state.conversation_context = []
  → Planner chỉ nhận context summary/digest, scope và trusted runtime
      ├─ allowed_use=none → không render caller
      └─ allowed_use=quote_only → lấy records từ registry
          → Output Guard raw + normalized → truncate/display escape
          → RenderPart(channel=caller_quote, source_class=caller_context)
          → guard part + assembled answer → final_answer có nhãn caller

Researcher prompt/input: không có caller context
Analyst prompt/input:   không có caller context
analysis_result:        chỉ có phân tích/evidence từ KB
```

Boundary giới hạn query 4.000 ký tự, tối đa 20 context messages, 4.000 ký tự
mỗi message và 30.000 ký tự context tổng. `role` chỉ chấp nhận user/assistant
hoặc absent; không được dùng làm provenance. Các field như claimed source,
verified hay quyền caller đưa thêm bị bỏ, còn record luôn unverified.

`_planner_graph_node` bỏ raw context/execution input; worker adapters chỉ
forward các key đã whitelist. Registry không nằm trong state caller có thể
tự cấp. Registry thiếu/đóng/sai run phải đi nhánh lỗi, không phục hồi bằng
caller data. `allowed_use` được Planner quyết định từ query/scope và cập nhật
registry; caller không được gửi field này như quyền điều phối.

Quote renderer lấy tối đa ba messages, tối đa 1.000 ký tự/message và 3.000
ký tự tổng, giữ nhãn chưa xác minh. Quote được phép xuất hiện ở final answer
không có nghĩa nội dung được model phân tích hoặc xác nhận. Source `both`
hiện cho KB analysis độc lập và caller quote riêng; không tổng hợp kết luận
từ caller. Direct Analyst ở ON từ chối context không rỗng/sai kiểu trước model;
evidence IDs và confidence dựa vào KB documents. OFF nhận context nguyên trạng.

### 2.5. Prompt Injection Defense và attack surfaces

| Checkpoint | Dữ liệu được kiểm tra | Xử lý thực tế và giới hạn |
| --- | --- | --- |
| Input Guard | `user_query`, không phải toàn bộ context | Pattern/context-aware risk scoring; ON chặn high và medium command/unresolved trước model; public OFF không gọi guard |
| Retrieval Guard | Từng field `content`, `title`, `source`, `document_id`, `chunk_id` | Quét riêng từng field; ON filter high hoặc medium có command detection; reporting/quote phân loại theo heuristic |
| KB policy | Managed trust, source allowlist, finite trust score, content hash | ON filter thiếu/sai metadata/hash hoặc trust thấp; policy filtering không phải PI detection |
| Analyst validation | Structured draft, evidence IDs, metadata của candidate | Loại unknown evidence/forged provenance; không chứng minh claim được nguồn hỗ trợ về ngữ nghĩa |
| Output Guard | Raw/normalized caller quote, từng RenderPart và assembled answer | Exact canary/fingerprint, disclosure-frame heuristic, secret patterns; ON refusal/redaction; không phát hiện mọi answer hijack |
| Action Gate | Tool + params + query/provenance/runtime task + approval | ON chặn context mismatch/missing confirmation, enforce allowlist/schema; OFF dispatch trực tiếp |

Input Guard có semantic hook cho medium risk, nhưng YAML hiện để
`semantic_classifier_enabled=false` và chưa tích hợp provider production.
Hook khi có provider được kiểm soát timeout/status/fallback; unavailable,
timeout hoặc malformed không được coi là negative. Command evidence không
bị negative semantic result vô hiệu. Medium unresolved ON vẫn fail-closed.
Không có universal LLM judge hoặc prompt similarity detector đã triển khai.

Researcher lọc candidate pool trước khi chọn top-k; số chunk bị lọc được
tách khỏi clipping theo K. Prompt hardening là lớp bổ sung, không thay guard.
Output Guard ưu tiên refusal khi có prompt-leak indicator; nếu chỉ match
secret pattern thì redact. Input Guard lỗi/contract sai, retrieval lỗi hoặc
runtime unavailable là operational error, không phải detection thành công.

### 2.6. Binding tool task và tương tác PI–CF

```text
execution_input = {tool_name, params} do caller gửi tại ingress
  → ExecutionRequest schema → immutable JSON snapshot trong runtime
  → model/Planner tạo execution_request candidate
  → Executor so tool + toàn bộ normalized params với snapshot
  → contextual Action Gate + allowlist/schema
  → callback ứng dụng cho write action nếu cần → tool execution
```

Self-digest của candidate chỉ phát hiện thay đổi sau planning; P5 bổ sung
so sánh với task caller đã capture trước model. `conversation_context`,
retrieved text và model prose không được cấp task binding hoặc approval.
`execution_input` có thẩm quyền xác định tác vụ caller yêu cầu, không xác nhận
records/file contents là đúng hoặc người gửi có danh tính đã xác thực.

`save_test_result` cần callback được cấu hình qua `build_workflow`; callback
nhận request bất biến có run ID/tool/digest/params. CLI chưa có UI approval,
không tự cấp write permission. Contextual gate có thể tắt qua config; ON cần
gate bật để enforce binding. OFF không chạy gate, không binding hoặc approval.

PI và CF có thể kết hợp nếu context spoofed chứa chỉ thị độc, nhưng hai cơ
chế can thiệp khác nhau: CF isolation cắt đường caller → Analyst; PI guard
kiểm tra query, KB/metadata và đầu ra. Context isolation không giải quyết
injection từ KB; Output Guard trên quote không thay provenance isolation.
Một chỉ thị plain text xuất hiện trong caller quote cũng không đồng nghĩa
model-level instruction adherence.

### 2.7. OFF/ON và điều kiện so sánh

Từ ngày 2026-10-06, public OFF là **`unprotected_off_v1`**. OFF dùng graph
`StateGraph` riêng với raw dict và reducer thay toàn state, không có `context_boundary`, public input schema,
trusted source registry hoặc worker adapters. Các flag phòng thủ OFF đều tắt;
graph không gọi detector, classifier bảo mật, canary builder hoặc Action Gate.
Route classifier là model chọn tác vụ, không phải security classifier.

```text
user_query + conversation_context + dữ liệu caller
  → Planner nhận raw context, chọn route bằng plain model.invoke
  → Researcher nhận shared state → semantic retrieval top-k, không security filter
  → Planner → Analyst nhận query + raw context + KB
  → analysis_result chưa schema/quality/provenance validation → Planner
  → nếu cần tool: model tạo tool_name/params từ cùng dữ liệu chưa xác minh
  → Executor gọi implementation trực tiếp → execution_result
  → Planner xuất kết quả không output guard, nhãn trust hoặc display escaping
  → final_answer + telemetry quan sát
```

OFF bỏ allowlist enforcement, request/result schema, task binding, approval,
path boundary, extension restriction, file/result size và record caps, overwrite
protection, process isolation và application tool timeout. Graph không dùng
giới hạn 25 bước mặc định của LangGraph. `execution_input` ở OFF là dữ liệu
gợi ý cho model, không phải bản xác nhận có thẩm quyền.

Graph edges, tên route, retrieval top-k/relevance, JSON/CSV parsing và điều kiện
toán học để tính metric là giao thức chức năng. Dispatcher chỉ có những tool
đã triển khai; bỏ allowlist không tạo thêm shell/network capability. Giới hạn
OS, bộ nhớ và provider vẫn tồn tại. Telemetry/attribution không chặn hoặc sửa
prompt/action/output. Gọi guard trực tiếp trong unit test có thể quan sát signal;
đó không phải đường public OFF.

ON giữ các cơ chế P1–P7. So OFF/ON mới đo toàn bộ stack phòng thủ, bao gồm
khác biệt prompt, schema, isolation và tool controls; chưa thể quy tác động cho
riêng một guard. Giữ cùng corpus, snapshot KB, model/config và rubric khi đo.
OFF không khôi phục tài liệu đã bị ingestion loại khỏi snapshot KB trước đó.

Artifact P1–P7 dùng OFF cũ có bảo vệ cấu trúc và được giữ nguyên. Profile mới
được ghi riêng bằng `workflow_profile_version=unprotected_off_v1`; rubric vẫn
là `evaluator_v2`. Observer đo raw output của OFF dưới kênh `mixed_unknown`,
không giả định provenance hoặc semantic correctness. Harness từ chối so báo cáo
thiếu/sai profile, dù cùng evaluator version; full/retrieval reports lưu dưới
`unprotected_off_v1/evaluator_v2/` để tránh ghi đè kết quả cũ.

CF harness đóng băng vẫn giữ matrix `A/on vs C/on` và giới hạn thực nghiệm cũ;
không tự chuyển nó sang OFF/ON mới hoặc cấp API authority. Muốn thực nghiệm
đối chứng mới phải chốt matrix/budget và attribution tương đương; evidence
thiếu vẫn là `unknown`.

## Chương 3. Kết quả kiểm chứng, giới hạn và kết luận nghiên cứu

### 3.1. Phân biệt trạng thái finding và mức bằng chứng

| Trạng thái | Ý nghĩa |
| --- | --- |
| Pending | Chưa triển khai |
| In progress | Đang xử lý, chưa đủ kiểm chứng |
| Fixed | Code sửa và test kỹ thuật phù hợp đạt; có named test/function/result |
| Validated | Có thực nghiệm/evaluator phù hợp; phải nêu mức validation và corpus/model/config |
| Deferred | Hoãn có lý do và điều kiện tiếp tục |

Backlog hiện có **19/19 finding R01–R19 = Fixed**, chưa có finding được
nâng thành model-level `Validated`. P1 đã kiểm chứng evaluator contract,
không đồng nghĩa model robustness. Kết luận tương ứng là đã sửa và kiểm
chứng các lỗi được nêu trên các testcase hiện có; không phải mọi PI/CF đã
được loại bỏ. Mapping theo ID và evidence chi tiết giữ trong backlog/artifacts.

### 3.2. Bằng chứng kỹ thuật có thể truy vết

Bảng dưới là evidence lịch sử P7, ứng với source export P7 và OFF cũ.
Không diễn giải các PASS của OFF cũ thành hành vi của `unprotected_off_v1`.

| Nội dung | Test/function và evidence | Kết quả đã ghi nhận |
| --- | --- | --- |
| CF source selection | `tests/test_context_guard.py::test_query_fixture_matches_deterministic_scope_contract` → `classify_scope_query` | PASS trong P7 clean export |
| CF/PI Analyst isolation | `tests/test_compiled_workflow.py::test_p2_forced_analysis_researches_first_and_uses_only_kb_task` → adapters/Analyst | PASS: retrieval/model input không nhận caller marker; quote riêng |
| Indirect PI downstream | `tests/test_compiled_workflow.py::test_retrieval_boundary_filters_before_each_downstream_model` → `guard_retrieval`/KB prompts | PASS cho research/analysis và OFF/ON với models stub |
| Analysis → tool substitution | `tests/test_compiled_workflow.py::test_p5_analysis_cannot_replace_records_confirmed_before_planning` → runtime binding/Action Gate | PASS: ON denied substituted records; OFF observed/executed stub |
| Trusted approval | `tests/test_compiled_workflow.py::test_p5_public_write_uses_only_trusted_scoped_approval` → callback/Executor | PASS cho missing/deny/approve/error/non-bool/changed-request cases |
| Evaluator | `tests/test_p1b_coordination_integrity.py::test_evaluator_v2_context_verdicts_use_final_parts_and_errors` → shared evidence/rubric | PASS: quote/echo/errors/unknown không bị chấm sai như generated-answer success |
| Acceptance route | `tests/test_compiled_workflow.py::test_p7_acceptance_script_matches_compiled_routes_and_confirmed_tool` → `run_acceptance` | PASS: bốn route × OFF/ON, guard thật/provider-tool stubs |
| Reproducibility | `regression_clean_export.xml`, `clean_export_verification.json`, `source_fingerprint.json` | 632 passed / 8 skipped, 0 failures/errors; export 123 file |

Các PASS trên được xác nhận từ JUnit P7; đây là evidence đã có, không phải
lượt chạy model mới khi soạn tài liệu. Tám skip là test baseline CF đóng băng,
không xem như tám test đã đạt. Export không có `.env*`, vector DB hoặc artifact
lịch sử lúc bắt đầu; dùng dependency environment đã cài, chưa chứng minh
fresh install/fresh Git checkout. 28 source/fixture còn untracked ở thời điểm
đóng P7; danh sách nằm trong `version_control_manifest.json` của P7.

### 3.2.1. Kiểm chứng OFF không bảo vệ ngày 2026-10-06

Chỉ bổ sung hai ca trong `tests/test_compiled_workflow.py`; tái sử dụng test
ON và cập nhật fixtures/mode của test cũ. Các test về isolation/envelope/runtime
registry chạy ở ON; OFF mới không được yêu cầu pass contract phòng thủ đó.
Không xóa module test hoặc thêm skip để bỏ qua failure.

| Evidence | Test + function | Kết quả và phạm vi |
| --- | --- | --- |
| OFF-CONTEXT | `test_unprotected_off_passes_raw_context_and_model_output_through_all_workers` → `BaselineWorkflow`, raw Planner/Analyst, direct executor | PASS: query/context vượt cap ON và metadata giả đi qua mọi worker/model input; draft confidence/evidence sai được giữ; tool ngoài allowlist thử nghiệm dispatch được; output >100 KB được giữ; không gọi guards/schema/isolated execution; không boundary/25-step limit |
| OFF-TOOLS | `test_unprotected_off_tools_remove_path_size_record_and_overwrite_limits` → baseline tool implementations | PASS: đọc fixture ngoài data root bằng relative/absolute path, bỏ byte/record caps; write đường dẫn tuyệt đối và extension bất kỳ, ghi đè không approval; chỉ dùng file tổng hợp trong tmp |
| ON-BINDING | `test_p5_analysis_cannot_replace_records_confirmed_before_planning`, `test_p5_public_write_uses_only_trusted_scoped_approval` | PASS: ON giữ binding/approval; OFF direct execution không gate event |
| PROFILE | `test_evaluator_v2_simulation_and_legacy_reports_are_not_measurements` → `comparable_reports`, save helpers | PASS: cùng rubric nhưng thiếu/sai profile không so được; thư mục mới tách lịch sử |
| Regression | `artifacts/unprotected_off_20261006/evaluator_v2/regression_clean_export.xml` | 592 passed, 8 skipped; models/search stubs, local tools; không gọi provider |

Số pass giảm so P7 do bỏ tổ hợp OFF khỏi test các contract chỉ thuộc ON,
không phải bằng chứng thiếu coverage ON. Tám skip vẫn là baseline CF đóng băng.
Snapshot, source hashes, named JUnit và xác nhận artifact lịch sử không đổi
được lưu trong cùng thư mục evidence. Kiểm chứng source export dùng dependency
environment hiện có; không khẳng định fresh install. OFF có đường truyền
attack surface là chứng minh cấu trúc; stub trả marker không chứng minh model
thật sẽ tuân theo injection. Không có ASR/FPR/model-level validation mới.

### 3.3. Kết quả tối ưu P6

P6 so sánh full GuardResult trước/sau trên **14 case OFF/ON** và ghi nhận
14/14 bằng nhau. Corpus tổng hợp cố định, có text/metadata lặp; ba warmup và
25 timing samples/case. Số đo ON từ artifact `comparison.json`:

| Case | Median trước (ms) | Median sau (ms) |
| --- | ---: | ---: |
| Input medium command (`input_1`) | 1,8995 | 0,2639 |
| Retrieval clean, 8 documents | 10,2944 | 2,2365 |
| Retrieval mixed, 32 documents | 37,3224 | 10,0137 |
| Settings load, warm parse cache | 1,8544 | 0,1355 |

Pure scan cache scoped theo guard call, tối đa 256 entries, copy list và clear
ở return/exception; YAML cache theo content/mode, tối đa tám templates, đọc
file mỗi lần và deep-copy settings. Không cache policy decision/approval.
Đây là bounded decision equivalence và số đo guard cục bộ, không phải tốc độ
toàn workflow, ASR/FPR, cold-start hay bằng chứng giảm memory peak.

### 3.4. Quy tắc evaluator và kết quả chưa có

`evaluator_v2` dựa trên structured final parts và đối chiếu rendered output
với final answer; assembled guard đổi output thì attribution trước đó không
được giữ như evidence của answer mới. Caller quote, runtime template và
`purpose=evidence_echo` không thuộc generated-answer objective. Harness CF
còn kiểm tra scope/provenance/analysis_result. Runtime error, thiếu attribution
hoặc simulation phải báo riêng; không chấm thành defense success.

ASR/FPR chính thức sau P1–P7 **chưa được đo trên model thật**. Khi đo phải
nêu eligible attack/benign denominator, errors/unknown và coverage; FPR của
PI detector tách khỏi KB source-policy filtering. Không dùng số test pass
làm detection rate, hoặc `final_output_affected=null` làm kết luận attack fail.
Các số liệu legacy trong README/artifact không được cộng vào metric mới
hoặc so trực tiếp với v2 khi thiếu evaluator attribution tương đương.

### 3.5. Bypass, rủi ro còn lại và giới hạn được xác định

| Điểm cần thảo luận | Mức bằng chứng và ảnh hưởng |
| --- | --- |
| Injection paraphrase/ngôn ngữ mới/không match signals | Giới hạn rule/scoring được ghi trong P3; input không có signals được phép. Đây là đường có thể lọt, chưa có PoC model-level mới xác nhận sau P7 |
| Prompt leak diễn đạt lại hoặc canary không đi qua builder | Exact marker/heuristic không bao phủ mọi disclosure; không tuyên bố universal prompt protection |
| KB có metadata/hash hợp lệ nhưng claim sai | Hash/provenance không xác thực semantic truth; validation evidence IDs không bảo đảm claim entailment. Không mở rộng thành defense cho mọi poisoning |
| Quote được người đọc hiểu nhầm là kết luận của hệ thống | Caller quote vẫn hiển thị dữ liệu chưa xác minh; nhãn và source separation giảm nhầm lẫn, chưa đánh giá human interpretation |
| Scope grammar chưa bao phủ mọi câu tự nhiên | Có thể hỏi lại hoặc chọn sai scope trên mẫu chưa đo; không tuyên bố semantic source selection tổng quát |
| Medium unresolved fail-closed | Có thể chặn benign query; cần FPR/utility thực nghiệm thay vì suy từ clean controls ít mẫu |
| Tắt guard/gate hoặc dùng API nội bộ ngoài public facade | Vi phạm assumptions/đổi cấu hình thí nghiệm, không phải PoC bypass public ON đã chứng minh |
| Caller task binding và callback policy | Binding ngăn model đổi task; không xác thực caller, nội dung dữ liệu hoặc chất lượng policy approval của ứng dụng |

Các blind spot đã tái hiện trước fix R01/R08/R09/R18, medium policy R02,
self-digest R03, source grammar R06 và caller evidence R13 có evidence sửa
trong backlog. Không tiếp tục ghi chúng như bypass đã xác nhận của source
cuối. Trong lượt cập nhật báo cáo này không chạy red-team/model mới; do đó
không bổ sung danh sách bypass ON thành công chưa có evidence.

### 3.6. Đánh giá kiến trúc và phần thực nghiệm còn thiếu

Kiến trúc đủ rõ để trình bày cơ chế defense-in-depth trong báo cáo: checkpoint
trước model, nguồn được tách, trusted runtime binding và final attribution
có thể kiểm chứng bằng test. Đóng góp CF hiện tại chủ yếu là **isolation và
quote-only rendering**, có đánh đổi utility: chưa phân tích/tổng hợp caller.
Đóng góp PI là các guard nhiều checkpoint với heuristics hữu hạn; không
chứng minh một bộ detector ngữ nghĩa tổng quát.

Để kết luận hiệu quả thực nghiệm cần smoke/model runs được phê duyệt budget,
corpus sạch và attack có objective rõ, cấu hình/corpus/evaluator hashes cố
định, repetitions và cách xử lý error/unknown. PI/CF có thể dùng profile OFF/ON
mới với attribution tương đương; CF matrix A/on–C/on cũ là thí nghiệm riêng.
Cần báo cả task
utility, quote-only limitation và operational coverage. Đây là việc còn
thiếu; tài liệu này không cấp phép chạy API hoặc tự tạo số ASR/FPR.

### 3.7. Kết luận dùng trong báo cáo

Hệ thống đã triển khai và kiểm chứng kỹ thuật các lớp phòng thủ cho Prompt
Injection và User-Originated Coordination Flaw qua conversation context.
Sau P1–P7, 19 finding được đóng ở mức Fixed; regression trên clean source
export P7 đạt 632 test, tám baseline test được skip theo thiết kế. OFF mới
`unprotected_off_v1` bỏ toàn bộ defense checkpoint; regression hiện hành đạt
592 test và tám skip. Đây là số test kỹ thuật, không phải tỷ lệ chống tấn công.
Kết quả chứng
minh các contract/isolation/checkpoint trên corpus test hiện có và khả năng
tái lập bằng source export trong môi trường dependency đã dùng. Hiệu quả
chống tấn công ở model-level, ASR/FPR và khả năng khái quát vẫn cần thực
nghiệm tiếp; các rủi ro chưa đo được giữ như giới hạn thay vì kết luận đã xử lý.

## Nguồn đối chiếu nội bộ

- [Security backlog và named evidence](SECURITY_FIX_BACKLOG.md).
- [OFF mới: acceptance và giới hạn](artifacts/unprotected_off_20261006/evaluator_v2/acceptance.json),
  [JUnit](artifacts/unprotected_off_20261006/evaluator_v2/regression_clean_export.xml),
  [source fingerprint](artifacts/unprotected_off_20261006/evaluator_v2/source_fingerprint.json).
- [P7 acceptance](artifacts/phase7_reproducibility/evaluator_v2/acceptance.json),
  [JUnit](artifacts/phase7_reproducibility/evaluator_v2/regression_clean_export.xml),
  [source fingerprint](artifacts/phase7_reproducibility/evaluator_v2/source_fingerprint.json).
- [P3 acceptance và giới hạn PI](artifacts/phase3_input_output/evaluator_v2/acceptance.json),
  [P4 CF acceptance](artifacts/phase4_context/evaluator_v2/acceptance.json),
  [P5 execution acceptance](artifacts/phase5_execution/evaluator_v2/acceptance.json).
- [P6 full-result/timing comparison](artifacts/phase6_optimization/evaluator_v2/comparison.json).
- [Hướng dẫn chạy và cấu hình](README.md), [fixture provenance](tests/fixtures/coordinator_flaw/README.md).

Artifact lịch sử nằm trong thư mục bị Git ignore. Khi bàn giao báo cáo phải
đính kèm evidence có hash tương ứng hoặc archive được chỉ định; source Git
đơn lẻ không tự chứa các evidence links này. Bản Word cùng nội dung được
lưu ở `Bao_cao_kien_truc_va_ket_qua_phong_thu.docx`.
