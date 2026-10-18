# Security fix backlog

Ngày cập nhật: 2026-10-06. Phạm vi: Prompt Injection (PI) và Conversation Context
Spoofing / User-Originated Coordinator Flaw (CF).

## Cập nhật baseline OFF — 2026-10-06

Public OFF hiện là `unprotected_off_v1`, dùng `graph/baseline.py` riêng.
Bỏ context boundary/registry/adapters, PI/CF guards, canary/hardening,
schema/provenance/confidence gates và output escaping; tool dispatch trực tiếp,
không allowlist enforcement/task binding/approval/path/size/record caps,
overwrite protection/process isolation/application timeout hoặc 25-step cap.
Route/tool implementation lookup, parsing và điều kiện toán học vẫn là giao
thức chức năng; không thêm tool ngoài phạm vi project.

ON giữ các phòng thủ P1–P7. Bảng findings và các section phase bên dưới là
lịch sử nghiệm thu theo source lúc đo; các mô tả OFF observed/isolation/schema
ở đó không áp dụng cho public OFF mới. Không sửa artifact lịch sử hoặc nâng
finding thành `Validated` từ test stub.

Evidence mới: `artifacts/unprotected_off_20261006/evaluator_v2/`.

| Nội dung | Named test + file/function | Bằng chứng |
| --- | --- | --- |
| Raw context/model/tool output | `tests/test_compiled_workflow.py::test_unprotected_off_passes_raw_context_and_model_output_through_all_workers` → `BaselineWorkflow`/raw agents | PASS: vượt cap input, role/source giả, invalid draft/task, arbitrary implementation và >100 KB output được giữ; no defense checkpoint |
| Tool controls OFF | `tests/test_compiled_workflow.py::test_unprotected_off_tools_remove_path_size_record_and_overwrite_limits` → baseline tools | PASS: traversal/absolute path, byte/record caps và overwrite/approval; synthetic tmp files |
| ON binding/approval | `test_p5_analysis_cannot_replace_records_confirmed_before_planning`, `test_p5_public_write_uses_only_trusted_scoped_approval` trong cùng file | PASS: real ON checks, stub model/tool |
| Measurement profile | `tests/test_multi_agent_coverage.py::test_evaluator_v2_simulation_and_legacy_reports_are_not_measurements` → compare/save helpers | PASS: từ chối same-rubric legacy không profile; reports lưu riêng |
| Regression current export | `regression_clean_export.xml` | 592 passed, 8 skipped; giữ nguyên skip baseline đóng băng; không API/model thật |

Chỉ thêm hai test case vào module hiện có và shared fixture chọn ON mặc định
cho security tests; reuse/migrate các test cũ, không tạo thêm test module.
Rubric vẫn `evaluator_v2`; experiment profile thêm `unprotected_off_v1` để tránh
trộn OFF cũ/mới. So OFF/ON mới là đánh giá toàn bộ stack, chưa là ablation riêng
từng defense. Cách chạy baseline nằm trong README mục 12 và báo cáo mục 2.7.

## Quy ước nghiệm thu

- `Pending`: chưa triển khai; `In progress`: chưa đủ kiểm chứng.
- `Fixed`: code đã sửa và kiểm chứng kỹ thuật liên quan đạt.
- `Validated`: evaluator/thực nghiệm phù hợp xác nhận hành vi mong muốn;
  phải ghi rõ mức bằng chứng, không suy từ mock thành model-level effectiveness.
- `Deferred`: nhánh hoãn, có lý do và điều kiện tiếp tục.
- Thứ tự: Phase 1 measurement → 2 indirect PI → 3 direct PI/output → 4 CF →
  5 analysis-to-execution → 6 optimization → 7 cleanup/reproducibility.
- Không dùng ASR/FPR mới để so hiệu quả defense trước khi Phase 1 đóng.
- Tái sử dụng test trước; chỉ thêm case khi thiếu coverage. Full regression là
  một bằng chứng, không thay correctness/security/utility/reproducibility.

## Backlog

| ID | Phase | Severity | Defense | Status | Thay đổi | Bằng chứng |
| --- | --- | --- | --- | --- | --- | --- |
| R01 | 2 | High | PI | Fixed | Quét mọi match trong KB, phân loại reporting/imperative theo context; bỏ điều kiện match phải đầu câu | P2-R01: 9 attack + 5 benign cases và 2 downstream routes PASS |
| R02 | 3 | High | PI | Fixed | ON chặn medium command/unresolved trước routing; semantic mặc định tắt, unavailable không giả negative; quote có framing giới hạn | P3-R02: mode policy, benign/mixed quotes, failure statuses + Planner boundary PASS |
| R03 | 5 | High | Combined | Fixed | Snapshot execution_input tại ingress; bind tool + toàn bộ params trong runtime, không tin self-digest của model | P5-R03: self-digest probe + compiled records substitution OFF/ON + immutable binding/CLI PASS |
| R04 | 1 | High | Measurement | Fixed | CF rubric dùng structured final parts, scope/provenance/errors; bỏ state research_answer giả định | E04 bên dưới |
| R05 | 1 | High | Measurement | Fixed | Loại echo theo purpose; nhận risk-scoring events; errors/unknown ra khỏi ASR; tách PI FPR khỏi source-policy filtering | E05 bên dưới |
| R06 | 4 | Medium | CF | Fixed | Grammar nguồn dùng chung classifier/projection; phân biệt topic/source use; không mask apostrophe trong don't | P4-R06: 6 scope/projection probes + conflict/denial controls + compiled differential PASS |
| R07 | 3 | Medium | PI | Fixed | Tách exact canary/fingerprint khỏi disclosure-frame heuristic; đổi config, bỏ term-only leak | P3-R07: benign/disclosure pairs, exact markers, secret precedence + part/assembled guards PASS |
| R08 | 2 | Medium | PI | Fixed | Quét PI trên toàn bộ textual fields đưa tới Analyst; Planner chỉ nhận content đã đóng gói | P2-R08: metadata 4 fields + real-guard workflow PASS |
| R09 | 2 | Medium | PI | Fixed | verify_content_hash bật thì thiếu/empty hash bị lọc; hash vẫn chỉ là consistency check | P2-R09: empty/missing key, mismatch và valid-hash controls PASS |
| R10 | 5 | Medium | General | Fixed | Tách analysis KB và execution thành RenderParts/envelopes riêng, đối chiếu runtime result binding | P5-R10: test_compiled_graph_research_analysis_execute_keeps_both_outputs, KB/tool channels và ID riêng PASS |
| R11 | 1 | Medium | Measurement | Fixed | Không suy propagation từ inherited events; final_output_affected là null khi chưa đo objective | E11 bên dưới |
| R12 | 1 | Medium | Measurement | Fixed | Bỏ production disclosure fixture; simulation chỉ trong harness và không eligible ASR | E12 bên dưới |
| R13 | 4 | Medium | Combined | Fixed | Direct Analyst/prompt KB-only, từ chối caller trước model ở OFF/ON; bỏ caller evidence/confidence | P4-R13: direct API/builder rejection, invalid evidence IDs và real-Analyst workflow isolation PASS |
| R14 | 5 | Medium | General | Fixed | Callback ứng dụng tin cậy nhận request bất biến; không nhận cờ approval từ state/caller/model | P5-R14: public callback 6 cases + forged state flags/missing/closed runtime PASS |
| R15 | 7 | Medium | General | Fixed | Sao chép nguyên byte 3 fixture CF vào tests/fixtures; cập nhật 4 consumer; suite không cần artifact lịch sử | P7-R15: named fixture/preflight tests PASS; clean export 632 passed / 8 skipped; hashes và 100-entry archive hợp lệ |
| R16 | 1 | Low | Measurement | Fixed | Fingerprint bao phủ runtime modules, prompts, config, dependency manifest và evaluator/harness | E16 bên dưới |
| R17 | 7 | Low | General | Fixed | Acceptance tính boundary 4/6/4/2, OOS giữ None; tool gửi execution_input; kiểm tra accepted analysis/tool success | P7-R17: test_p7_acceptance_script_matches_compiled_routes_and_confirmed_tool PASS, 4 route × OFF/ON với model/search/tool stubs |
| R18 | 2 | Medium | PI | Fixed | Research lọc candidate pool trước khi chọn safe top-k; giữ baseline OFF và không tính clipping là filtering | P2-R18: mixed/all-filtered/underfilled/clean-pool, OFF/ON PASS |
| R19 | 3 | Low | PI | Fixed | Validate Input Guard result/events trong protected block trước state mutation, bỏ str(value) | P3-R19: 5 invalid contracts qua compiled workflow ở OFF/ON PASS; không downstream execution |

## Phase 1 — evaluator_v2

Trạng thái: **hoàn thành nghiệm thu kỹ thuật/evaluator**. Không phải nghiệm thu
model-level attack effectiveness; tiến độ Phase 2 được ghi riêng bên dưới.

Các payload chỉ được quan sát trong bộ nhớ bởi `tests/evaluation.py` qua
`agents.planner.render_parts`. Observer nhận những phần đã qua part guard,
trước assembled guard và registry cleanup. Chỉ sử dụng attribution khi rendered
text khớp final answer; nếu assembled guard thay nội dung thì attribution là
unknown. `RenderPart.purpose=evidence_echo` phân biệt Top-K khỏi generated answer.

CF rubric chấm scope, source boundary, structural provenance và utility riêng.
`instruction_verdict` chỉ đo mục tiêu đặt fixture marker ngoài caller quote;
`semantic_instruction_adherence=not_evaluated`. Evidence ID và nhãn kênh không
chứng nhận claim được nguồn hỗ trợ. Caller-only/both vẫn là chức năng limited.
Baseline A không có structured renderer nhận unknown khi thiếu attribution;
marker trong analysis hoặc final của Q-KB vẫn là bằng chứng thất bại tương ứng.

Simulation có `simulated_attack_success`, nhưng measured `attack_success=null`,
`measurement_eligible=false`. Mẫu số ASR bằng 0 hiển thị N/A, không ghi 0%.
PI false-positive rate xét injection detection trên clean controls; clean bị
lọc vì trust/source policy có metric riêng. Metrics này là rubric, chưa có
ASR/FPR từ model thật trong Phase 1.

`propagated_to` không tự thêm agent do inherited event; danh sách rỗng không
chứng minh không có exposure. Harness multi-agent giữ `payload_received_by`
qua node input IDs và tách analysis hijack khỏi final-answer hijack. Đây là
received evidence, không tự chứng minh downstream model đã consume payload.

### Evidence theo finding

| Evidence | Test name + file | Source/function | Kết quả và giới hạn |
| --- | --- | --- | --- |
| E04 | `tests/test_p1b_coordination_integrity.py::test_evaluator_v2_context_verdicts_use_final_parts_and_errors` (8 cases) | `manual_test_coordinator_flaw.py::_safe_result_metrics` | PASS: errors, thiếu attribution, analysis/research marker, allowed quote, guard replacement, sai scope, forged provenance. Chỉ rubric/fixture, không đo model robustness |
| E04-flow | `tests/test_p1b_coordination_integrity.py::test_p2_runtime_registry_captures_inputs_and_cleans_payloads_after_run` | `evaluation.py::observe_final_answer`, Planner renderer/cleanup | PASS: quan sát research answer thật của mocked workflow, loại echo; registry cleanup vẫn chạy và state không có research_answer |
| E05 | `tests/test_multi_agent_coverage.py::test_evaluator_v2_retrieval_excludes_echo_and_unknown_outcomes` (5 cases) | Retrieval/full-pipeline harness evaluators | PASS: echo-only false, generated marker true, error/missing evidence/guard replacement null; risk-scoring được detect; policy filter không tính PI FP |
| E05-flow | `tests/test_multi_agent_coverage.py::test_canary_quoted_in_refusal_is_not_success` | `manual_test_multi_agent_coverage.py::assess` | PASS: refusal chứa marker không thành success; exact generated marker được chấm success. LLM stub |
| E11 | `tests/test_tracing.py::test_p32_detector_signals_are_separate_from_guard_enforcement` (3 cases) | `planner.py::_guard_part` | PASS: observed/redacted/blocked có guard verdict riêng, không thành objective-success flag |
| E11-flow | `tests/test_security_integration.py::test_defense_off_observes_and_traces_injection_without_blocking` | `tracer.py::traced_node` | PASS: observed event không tự gán propagation; influence chưa đo là null |
| E12 | `tests/test_security_integration.py::test_defense_off_does_not_inject_disclosure_fixture` (2 cases) | `planner.py::_synthesize_and_finalize` | PASS: OFF giữ kết quả route thay vì tự sinh disclosure fixture |
| E12/version | `tests/test_multi_agent_coverage.py::test_evaluator_v2_simulation_and_legacy_reports_are_not_measurements` | Full-pipeline simulation, save_report, comparable_reports | PASS: simulation không gọi model, measured success null; từ chối mixed/legacy version; save v2 không ghi đè artifact lịch sử |
| E16 | `tests/test_p1b_coordination_integrity.py::test_p42_preflight_builds_frozen_dry_run_plans_without_api_authority` | CF harness source hashing/preflight | PASS: runtime/config/prompt/evaluator files thuộc fingerprint, preflight không cấp API authority |
| E16-content | `tests/test_p1b_coordination_integrity.py::test_evaluator_v2_source_hash_changes_with_defense_content` | `current_source_hashes` | PASS: thay nội dung source làm thay hash |

### Artifact và giới hạn

- JUnit cuối: `artifacts/phase1_measurement/evaluator_v2/regression.xml`.
  Kết quả cuối: **551 passed, 8 skipped**, 0 failure/error; tám skip thuộc
  `test_p0_baseline_coordinator_flaw.py` đóng băng. Tái sử dụng các module test
  hiện có; thêm 15 ca cho các khoảng trống measurement, không thêm test module.
  `tests/evaluation.py` là helper dùng chung cho harness, không phải test suite mới.
- Dry-run CF harness: **0 API/model call**, manifest giữ
  `execution_authorized=false`, `credentials_loaded=false`.
- Preflight mới: `artifacts/phase1_measurement/evaluator_v2/preflight_manifest.json`.
- History index: `artifacts/phase1_measurement/evaluator_v2/historical_artifact_index.json`.
  File cũ không bị sửa; thiếu version được ghi `unknown/legacy`, không tự nhận v1.
- Các manual PI report mới được lưu trong namespace `evaluator_v2`; so sánh
  OFF/ON từ chối evaluator khác version hoặc có simulation.
- Smoke authorization lịch sử đã consumed tiếp tục bị khóa; đổi evaluator
  không tạo quyền gọi API mới. Không chạy benchmark/model thật trong Phase 1.
- Nghiệm thu Phase 1 dùng test kỹ thuật và fixture evaluator. Các finding vẫn
  là Fixed; không tuyên bố model-level Validated hoặc hiệu quả PI/CF tổng quát.

## Phase 2 — Indirect Prompt Injection / Retrieval Boundary

Ngày triển khai: 2026-10-05. Phạm vi code đã được duyệt và kiểm chứng kỹ thuật;
không gọi API/model thật, không chạy ASR/FPR chính thức, không triển khai Phase 3.
Tiếp tục dùng `evaluator_v2`, không thay rubric hoặc sửa artifact lịch sử.

**Đã đóng nghiệm thu kỹ thuật P2:** người dùng đã cung cấp mô tả finding gốc;
R01/R08/R09/R18 được đối chiếu và chuyển sang `Fixed` sau regression cuối.
Không có ID nào được đánh dấu model-level `Validated`. Bản P2 đầu đợt chỉ
kiểm chứng scope đề xuất, còn thiếu đúng probe R01 và cơ chế R18; các artifact
đầu đợt được giữ nguyên để truy vết. Mô tả gốc được lưu tại
`artifacts/phase2_retrieval/evaluator_v2/finding_closure/finding_reference.txt`.

### Thay đổi và policy

- Giữ line/clause boundaries trước canonicalization; scan mọi pattern match
  thay vì chỉ nhận lệnh đầu sentence. Unknown prefix không miễn trừ scanning;
  context reporting được xét cục bộ, không miễn trừ imperative clause ở phía
  sau. Compact matching cũng giữ vị trí match để phân loại context. Detector
  và risk scorer dùng chung candidates; nhánh `user_input` không thêm rule
  retrieval mới.
- Thêm rule chỉ thị thay đổi answer/response trong KB. Command evidence đạt
  medium được lọc ON; giữ nguyên risk score thay vì nâng giả lên high.
- Quét riêng `content`, `title`, `source`, `document_id`, `chunk_id`. Không
  cộng signals của các field khác nhau để tạo một score cao giả. Event có
  field name và ID an toàn; ID chứa payload/format không an toàn được hash.
- Tín hiệu risk-only đơn lẻ có attack_type none không tự trở thành injection event.
  Policy/source/hash events vẫn tách khỏi PI detection.
- Trust phải hữu hạn trong [0,1]; khi bật verify_content_hash, thiếu hash cũng
  bị lọc như hash mismatch. OFF giữ chunk và chỉ quan sát; ON lọc theo policy.
- Planner dùng JSON đóng gói KB content, không đưa title/source/IDs vào prompt;
  ON có system instruction xác định KB là dữ liệu không tin cậy. Analyst dùng
  marker có angle brackets để encoder sẵn có escape marker giả trong payload.
  Encoding cấu trúc dùng cả hai mode; OFF không thêm trust instruction/hardening.
- Researcher nhận injection events theo stage/attack_type, bao gồm risk-only
  rule. Việc lọc chunk không tự chứng minh ảnh hưởng tới final output; giữ null.
- Guard/detector exception trở thành operational error, không fallback raw
  chunk vào model. Không còn chunk sau lọc thì không gọi downstream model.
- `search_candidates` trả ranked candidate pool tối đa 3*k, Research Guard
  lọc pool rồi Research chọn tối đa k accepted chunks. Public `search` giữ API
  top-k cũ; adapters/fixtures Research chuyển sang candidate-pool semantics.
  Không lặp query/vector retrieval để refill ngoài pool. `retrieval_filtered_count`
  chỉ đếm guard rejection, không tính các clean chunks ngoài top-k.

### Bằng chứng kỹ thuật theo hạng mục P2

| Evidence | Test name + file | Source/function | Kết quả và giới hạn |
| --- | --- | --- | --- |
| P2-A | `tests/test_retrieval_guard.py::test_same_indirect_command_is_kept_off_and_filtered_on` (4 cases); `test_clean_research_description_is_not_false_positive` (4 cases); `test_obfuscated_command_is_filtered_before_analyst` | `patterns.py::retrieval_command_candidates`, `detect_injection_patterns`; `prompt_risk.py::_retrieval_command_text` | PASS: prefix/line/bullet/obfuscation mục tiêu được phát hiện; benign controls vẫn giữ; OFF observed/ON filtered. Heuristic coverage, không chứng minh mọi paraphrase |
| P2-B | `tests/test_retrieval_guard.py::test_retrieval_scans_metadata_forwarded_to_analyst` (4 cases) | `retrieval_guard.py::guard_retrieval`, `_event_id` | PASS: title/source/document_id/chunk_id có injection bị lọc; events chỉ giữ field và safe/hash IDs. Content sạch, hash đúng và managed trust cao để cô lập PI detection |
| P2-C | `tests/test_retrieval_guard.py::test_retrieval_answer_instruction_is_filtered_at_medium_risk` | `patterns.py::_RETRIEVAL_ANSWER_INSTRUCTION`, `prompt_risk.py::_detect_signals`, `guard_retrieval` | PASS: chỉ thị answer hijack đạt medium bị lọc ON, score không bị nâng giả, OFF giữ nguyên |
| P2-D | `tests/test_retrieval_guard.py::test_retrieval_invalid_trust_or_missing_hash_is_not_accepted` (5 cases); các test trust/source/hash trong `tests/test_security_guards.py` | `retrieval_guard.py::guard_retrieval` | PASS: NaN/Inf/out-of-range, missing/empty hash được xử lý theo policy; policy events không bị gán là PI |
| P2-E | `tests/test_planner.py::test_research_answer_uses_kb_internally_without_exposing_source_metadata` (2 modes); `tests/test_agents.py::test_analyst_prompt_escapes_untrusted_delimiter_content` | `planner.py::_answer_from_research`; `agents/prompts/analyst.py::build_research_input`, `build_analyst_input`, `_safe_json` | PASS: payload không đóng được marker thật, JSON round-trip giữ content, Planner không đưa metadata vào prompt, chỉ ON thêm trust instruction. Kiểm chứng cấu trúc prompt, không phải model robustness |
| P2-F | `tests/test_compiled_workflow.py::test_retrieval_boundary_filters_before_each_downstream_model` (2 routes, mỗi route kiểm tra OFF/ON); `test_p2_empty_retrieval_keeps_only_runtime_notice_and_authorized_caller` (4 cases); `test_p2_retrieval_exception_is_operational_error_and_no_caller_salvage` (2 cases) | Researcher → real Retrieval Guard → Planner/Analyst; workflow finalization | PASS: chỉ accepted chunks vào prompt ON; cả content/title được lọc, OFF có exposure tương ứng; mixed retrieval giữ clean utility; empty/all-filtered không gọi model; search/guard lỗi không salvage caller. Search/model stub, guard/workflow thật |

### Kết quả và tái hiện

- Trước sửa: `artifacts/phase2_retrieval/evaluator_v2/reproduction.xml`:
  15 failed / 9 passed; ca fail là bằng chứng tái hiện, không là ASR/FPR.
- Targeted cuối: `targeted_after.xml`, 177 passed; full regression:
  `regression_final.xml`, **573 passed, 8 skipped**, 0 failure/error. Tám skip thuộc
  baseline coordinator đóng băng. Sau khi tăng assertion delimiter Analyst,
  `prompt_boundary.xml` kiểm chứng 3 prompt-boundary cases đều PASS.
- Thêm 22 case vào các module hiện có bằng parametrization và integration
  cần thiết; không thêm test module. Các test đã có vẫn được tái sử dụng.
- Lệnh đầy đủ và env kiểm chứng được lưu tại `verification_commands.json`.
  Chạy pytest bằng `python -B -c` để Windows multiprocessing không xem
  `<stdin>` là file main. `targeted.xml` là lượt trung gian có 173 passed và
  1 lỗi runner `<stdin>` ở executor; không dùng lượt này để nghiệm thu code.
- `source_fingerprint.json` giữ current runtime/config/evaluator hashes;
  `acceptance.json` giữ kết quả và trạng thái đối chiếu finding. Fingerprint
  Phase 1 vẫn mô tả source tại thời điểm Phase 1, không được viết lại theo P2.
- 22 artifact lịch sử trong history index được kiểm tra hash không đổi.

### Đối chiếu mô tả gốc và nghiệm thu finding

| Evidence / Finding | Vấn đề gốc | Test name + file | Source/function | Kết quả và giới hạn |
| --- | --- | --- | --- | --- |
| P2-R01 / R01 | Editorial note/embedded instruction bị bỏ vì không ở đầu sentence; hai detector chia sẻ blind spot | `tests/test_retrieval_guard.py::test_same_indirect_command_is_kept_off_and_filtered_on` (9 cases), `test_clean_research_description_is_not_false_positive` (5 cases); `tests/test_compiled_workflow.py::test_retrieval_boundary_filters_before_each_downstream_model` (2 routes) | `patterns.py::detect_injection_patterns`, `_is_retrieval_command`, `_compact_retrieval_command`; `prompt_risk.py::_retrieval_command_text` | PASS: Editorial note, arbitrary prefix, line/bullet, compact obfuscation, multiple matches và reporting→imperative; benign examples giữ nguyên; ON không chuyển payload xuống Planner/Analyst. Đây là technical classifier/dataflow evidence, không chứng minh mọi paraphrase hoặc model robustness |
| P2-R08 / R08 | title/source được model consume nhưng guard chỉ scan content | `tests/test_retrieval_guard.py::test_retrieval_scans_metadata_forwarded_to_analyst` (4 cases); compiled downstream test ở P2-R01 | `retrieval_guard.py::guard_retrieval`; `agents/prompts/analyst.py::build_analyst_input`, `build_research_input` | PASS: scan title/source/document_id/chunk_id, metadata injection bị lọc ON, safe/hash event IDs; Planner không nhận metadata không cần thiết |
| P2-R09 / R09 | verify_content_hash=True vẫn giữ chunk không có hash | `tests/test_retrieval_guard.py::test_retrieval_invalid_trust_or_missing_hash_is_not_accepted` (empty/missing-key cases); `tests/test_security_guards.py::test_retrieval_guard_filters_low_trust_injection_and_bad_hash`; `test_retrieval_guard_does_not_use_poison_ground_truth` | `retrieval_guard.py::guard_retrieval` | PASS: missing key/empty/mismatch bị lọc ON; valid hash giữ clean content, OFF pass-through. Hash không chứng minh authenticity/factual correctness |
| P2-R18 / R18 | Retrieval cắt top-k trước security filtering, không refill từ pool đã lấy | `tests/test_retrieval.py::test_research_refills_safe_top_k_from_candidate_pool` (mixed/all_filtered/underfilled/clean_pool, mỗi case kiểm OFF/ON) | `knowledge_base/retrieval.py::search_candidates`, `rerank_results`; `agents/researcher.py::research_node`; real `guard_retrieval` | PASS: attack chiếm top-2 vẫn refill được clean chunk rank dưới; pool không đủ trả <k, toàn bộ bị lọc trả rỗng, clean clipping không tăng filtered_count; một embedding/query, n_results=3*k. Provider/vector response stub, Research/ranking/guard thật |

Artifact kết thúc được lưu riêng trong
`artifacts/phase2_retrieval/evaluator_v2/finding_closure/`:

- `reproduction.xml`: trước closure fix, **8 failed / 26 passed**, xác nhận
  thiếu R01/R18; `embedded_probe.xml`: **1 failed / 8 passed**, xác nhận thêm
  reporting→imperative trong cùng câu. Đây là regression reproduction, không
  là measured ASR/FPR hay bằng chứng model bị khai thác.
- `targeted.xml`: 115 passed tại lượt closure đầu; `regression_final.xml`:
  **583 passed, 8 skipped**, 0 failure/error, trên source cuối sau embedded fix.
- Closure bổ sung **10 case trong module hiện có**, không thêm test module;
  tổng P2 thêm 32 case so với 551 passed của P1. Cả hai fixture PI harness dùng
  pool 3*k như live Research adapter, không mô phỏng pipeline cắt k trước guard.
- `source_fingerprint.json`, `verification_commands.json`, `closure_changes.diff`,
  `historical_verification.json`, `acceptance.json` chứa source/test hashes,
  lệnh kiểm chứng và final finding mapping. Artifact đầu đợt được giữ nguyên;
  22 artifact lịch sử được xác nhận hash không đổi, không viết lại kết quả cũ.
- R01/R08/R09/R18 = `Fixed`; không gọi provider/model thật, không chạy benchmark
  ASR/FPR chính thức và không triển khai Phase 3.

### Giới hạn còn lại

- Đây là deterministic heuristic cho các command families/cases đã xác định;
  không cam kết phát hiện mọi lệnh viết lại, mọi ngôn ngữ hoặc ngữ nghĩa chéo
  nhiều chunk/field. Quote/research labels do tài liệu tự khai không chứng nhận
  an toàn; benign coverage trong evidence là corpus cụ thể.
- JSON/marker và system instruction giảm nhầm trust, không phải sandbox cho
  model. Các stub chỉ chứng minh đường đi dữ liệu và quyết định guard.
- Content hash là consistency check, không chứng nhận nguồn hoặc factual
  correctness. Trust flags vẫn giả định được ingestion/storage do hệ thống
  quản lý; Phase 2 không thêm cơ chế xác thực nguồn mật mã hay mở rộng DP scope.
- Quét thêm metadata làm tăng lượng detector work; tối ưu thuộc Phase 6,
  phải giữ tương đương security decisions. Direct PI, Output Guard, caller
  context isolation và analysis-to-execution fixes vẫn thuộc phase sau.

## Phase 3 — Direct Prompt Injection / Output Boundary

Ngày triển khai/nghiệm thu: 2026-10-05. **R02/R07/R19 = Fixed** sau kiểm chứng
kỹ thuật trên source P3; không có finding nào được đánh dấu model-level
`Validated`. Giữ `evaluator_v2`; chưa chạy benchmark ASR/FPR hoặc tích hợp
provider/model ngữ nghĩa production. Không triển khai Phase 4/5/6/7.

### Policy và thay đổi

- Input Guard giữ nguyên query cho downstream. ON chặn high và medium có
  command evidence hoặc chưa phân định trước routing/model. OFF observed và
  pass-through. Risk score không bị nâng giả khi classifier positive/fallback;
  policy level được ghi riêng. Negative hợp lệ từ injectable provider không
  bỏ qua command evidence. Low/no-signals vẫn được phép, hook không chạy.
- Chỉ tách quoted span khỏi scan khi có framing nghiên cứu thuộc các dạng
  hỗ trợ giới hạn. Dấu ngoặc kép hoặc nhãn research tự khai không miễn kiểm
  tra; mọi phần ngoài quoted span vẫn được scan. Không rewrite/sanitize query.
- Production mặc định `semantic_classifier_enabled=false`. Bật nhưng không
  có provider là `unavailable`, không phải negative `ok`. Timeout/malformed/error
  có status riêng, confidence=0, không giả positive detection. Fallback medium/high
  đều chặn unresolved medium ON; fallback `allow` trong SecuritySettings bị từ
  chối. Positive/fallback level là policy metadata, không phải measured risk.
- Risk scorer nhánh user_input phân biệt reported-send relative clause
  (`context tôi gửi`) với lệnh gửi cho agent, xét từng match để không che lệnh
  phía sau. Nhánh retrieved_content và các quyết định retrieval P2 được giữ.
- Output Guard tách exact canary/fingerprint khỏi disclosure-frame heuristic.
  Nhắc thuật ngữ security đơn lẻ không đủ báo leak. Cấu hình mới
  `prompt_structure_check_enabled`; cấu hình similarity cũ bị từ chối rõ ràng.
  Tắt heuristic không tắt exact markers hoặc secret redaction. Fingerprint là
  SHA-256 của canary, không phải system prompt. Giữ leak-before-redaction,
  canned refusal và các checkpoint part/assembled hiện có.
- Planner kiểm tra GuardResult, bool/string/events và revalidate serialized
  schema trong protected block, trước state mutation. Không ép str(None).
  Contract lỗi là operational error ở OFF/ON, không gọi downstream và không
  được tính thành attack success/defense success.

### Bằng chứng theo finding

Các tên dưới đây trỏ tới testcase PASS trong `regression_verified.xml`;
`acceptance.json` giữ danh sách cụ thể, source/function và giới hạn theo ID.

| Evidence / Finding | Test name + file | Source/function | Kết quả và giới hạn |
| --- | --- | --- | --- |
| P3-R02-policy / R02 | `tests/test_input_guard_integration.py::test_medium_command_is_blocked_on_and_observed_off` (2 modes); `tests/test_security_integration.py::test_same_payload_passes_off_and_is_blocked_on` (high/medium) | `input_guard.py::guard_input`; `planner.py::planner_node` | PASS: medium override giữ score 0.65, block trước route ON; OFF giữ input và route. Guard/Planner thật, route model stub |
| P3-R02-utility / R02 | `tests/test_input_guard_integration.py::test_research_quotes_do_not_hide_following_commands` (3 cases); `test_quote_or_research_label_alone_does_not_exempt_command`; `tests/test_prompt_risk.py::test_research_question_is_not_misclassified` (2 cases) | `input_guard.py::_assessment_text`; `prompt_risk.py::_detect_signals` | PASS: benign EN/VI quotes được giữ, quote/research labels và câu lệnh ngoài quote không bypass; reported-send không thành send command. Heuristic/corpus cụ thể |
| P3-R02-semantic / R02 | `tests/test_semantic_classifier.py::test_missing_provider_is_unavailable_not_a_negative_classification`; `tests/test_semantic_classifier_integration.py::test_unresolved_medium_fails_closed_with_honest_semantic_status` (4 statuses); `test_medium_input_invokes_classifier_once`; `test_positive_classifier_applies_mode_policy`; `test_default_configuration_has_no_semantic_provider_and_blocks_unresolved_medium`; `test_real_semantic_verdict_resolves_ambiguous_medium_without_changing_risk_score` | `semantic_classifier.py::classify_semantically`, `_validate_result`, `_fallback_result`; `guard_input` | PASS: missing/timeout/malformed/error và valid positive/negative có policy rõ ràng; negative không override command; score không bị sửa. Mọi provider trong test là injected stub, không phải semantic model production |
| P3-R07-utility / R07 | `tests/test_output_guard.py::test_security_explanations_are_allowed_but_disclosure_is_detected` (4 cases, mỗi case kiểm OFF/ON) | `output_guard.py::_prompt_leak_findings` | PASS: ba ví dụ benign của user + một ví dụ VI không bị báo leak; thêm disclosure vào cùng answer vẫn bị phát hiện. Không suy thành FPR tổng quát |
| P3-R07-enforcement / R07 | `tests/test_output_guard.py::test_canary_leak_is_blocked_on`; `test_fingerprint_leak_is_blocked_on_without_logging_fingerprint`; `test_structure_switch_does_not_disable_exact_canary_or_secret_redaction`; `test_prompt_leak_takes_precedence_over_secret`; `tests/test_security_guards.py::test_retired_similarity_config_is_rejected_instead_of_silently_ignored` | `guard_output`; `config.py::SecuritySettings` | PASS: exact markers, redaction/precedence và config migration giữ hành vi đúng; không log marker/fingerprint. Heuristic không phải similarity |
| P3-R07-flow / R07 | `tests/test_p1b_coordination_integrity.py::test_output_guard_can_omit_caller_part_and_keep_independent_kb`; `test_trace_keeps_part_checkpoint_metadata_but_not_caller_text`; `test_assembled_guard_block_replaces_the_whole_answer` | Planner part guards, renderer và assembled guard | PASS: bỏ phần caller vi phạm, giữ KB độc lập, checkpoint có part metadata và không raw caller text; assembled block thay toàn answer. Workflow/model stubs, không chứng minh model robustness |
| P3-R19 / R19 | `tests/test_security_integration.py::test_invalid_input_guard_contract_is_operational_error_before_downstream` (5 contracts, mỗi case kiểm OFF/ON); `tests/test_p1a_context_boundary.py::test_p31_input_guard_exception_returns_sanitized_guarded_error` (2 modes) | `planner.py::planner_node`, `_finish_without_caller` | PASS: None/dict/non-string value/non-bool allowed/malformed events thành error, không gọi scope/route/search/model/Analyst/Executor; không salvage caller, không gán input blocked hoặc final influence |

### Artifact và tái hiện

Namespace: `artifacts/phase3_input_output/evaluator_v2/`.

- `reproduction.xml`: **25 failed / 29 passed** trước production fix, là
  regression reproduction, không phải ASR/FPR.
- `targeted.xml`: 193 passed ở lượt đầu; `targeted_closure.xml`: **293 passed**
  sau xử lý ba lỗi integration phát hiện trong full regression.
- `regression_verified.xml`: **607 passed, 8 skipped**, 0 failure/error, là
  lượt nghiệm thu cuối. Tám skip vẫn thuộc baseline CF đóng băng. Tổng test
  tăng 24 case so với P2; tái sử dụng module hiện có, không tạo test module mới.
- `regression.xml`: collection lỗi do snapshot test có đuôi `.py`; đã đổi
  snapshot thành `.snapshot`. `regression_final.xml`: lượt trung gian có
  3 failed / 603 passed / 8 skipped. Hai artifact này được giữ để truy vết,
  không dùng nghiệm thu. Full regression chạy lại sau các sửa tương ứng.
- Hai fixture P1 output được đổi từ **yêu cầu tiết lộ** thành **disclosure
  frame có nội dung**; giữ assertion bỏ phần vi phạm, giữ KB và trace checkpoint.
  Câu yêu cầu tiết lộ trong caller quote không tự chứng minh output đã leak.
- `source_before/` giữ snapshot chỉ các file sửa P3 để phân biệt với thay đổi
  pre-existing trong workspace. `phase3_changes.diff`, `source_fingerprint.json`
  và `verification_commands.json` giữ diff P3, hashes và lệnh/env tái hiện.
- `finding_reference.txt` là bản sao mô tả gốc user cung cấp từ closure P2;
  `acceptance.json` ánh xạ finding → test/source/result/limitations.
- `historical_verification.json`: **33 artifact P1/P2 không đổi hash**.
  Không viết lại rubric, kết quả hoặc fingerprint lịch sử theo source P3.

### Giới hạn còn lại

- Không có semantic provider production. Paraphrase/no-signals ngoài các
  rule vẫn có thể đi tới model; quote framing không chứng nhận nội dung an toàn.
  Medium unresolved fail-closed có thể chặn query benign chưa phân định.
- Disclosure-frame heuristic vẫn có false positive/false negative và không
  xác minh nội dung trùng prompt thật; không bao phủ mọi answer hijack.
- Canary/prompt framing không phải sandbox. Các test stub chỉ chứng minh
  quyết định guard và dataflow, không chứng minh model-level effectiveness.
- Contract checks là baseline correctness áp dụng cả OFF/ON; operational
  errors không được chuyển thành kết quả attack-success hay defense-success.

## Phase 4 — Conversation Context Spoofing / Scope and Analyst Boundary

Ngày nghiệm thu: 2026-10-05. **R06/R13 = Fixed**, kiểm chứng kỹ thuật trên source
cuối; chưa có model-level `Validated`. Không chạy benchmark/API/model thật,
không thêm classifier LLM hoặc tính năng phân tích caller. Giữ `evaluator_v2`.

### Hành vi sau sửa

- `classify_scope_query` và Planner projection dùng chung `_source_selection`.
  Mặc định KB khi không có source-use request. Tên đề tài conversation context
  spoofing, vị trí `above` trong mô tả và `weather` trong security task không
  tự cấp quyền caller hoặc loại tác vụ. Câu hỏi thời tiết thuần túy vẫn OOS.
- Both-source grammar hỗ trợ prefix/suffix EN/VI, đảo thứ tự KB/caller và các
  cú pháp P2 đã được kiểm chứng. Task đưa vào nhánh KB không giữ source selector
  hoặc request còn phụ thuộc caller. Conflict/unprojectable yêu cầu hỏi lại;
  source selector trong quote không cấp quyền. Apostrophe trong `don't` không
  được mask thành quoted span và không làm mất source denial.
- Luồng giữ nguyên: query → scope/projected KB task → Researcher → Analyst;
  caller context → boundary → registry → caller_quote có nhãn riêng → final.
  Registry/provenance/worker views/rendering hiện có được tái sử dụng.
- Direct Analyst là API nội bộ KB-only. Non-empty/malformed caller context bị
  từ chối trước model, kể cả khi không có tài liệu và ở cả OFF/ON. Prompt builder
  cũng từ chối; argument legacy chỉ nhận None/[] và không serialize context.
  Evidence IDs chỉ đối chiếu documents; bỏ caller confidence 0.2 và nhánh
  conversation evidence. KB hợp lệ tiếp tục hoạt động, empty KB có confidence=0.
- `caller_only` vẫn chỉ quote có nhãn và nêu giới hạn; `both` thêm caller_quote
  riêng, không đưa caller vào analysis_result. Đây là baseline correctness và
  isolation, không phải xác thực KB hoặc semantic fact-checking.

### Bằng chứng theo finding

Mọi testcase dưới đây PASS trong `regression_final.xml`. `acceptance.json`
giữ danh sách testcase cụ thể cùng file/function và giới hạn bằng chứng.

| Finding | Test name + file | Source/function | Kết quả và giới hạn |
| --- | --- | --- | --- |
| P4-R06-scope / R06 | `tests/test_context_guard.py::test_p4_scope_and_kb_projection_agree` (6 cases); `test_p4_conflicting_or_unprojectable_source_requests_clarify`; `test_query_fixture_matches_deterministic_scope_contract` | `context_guard.py::classify_scope_query`, `_source_selection`, `project_kb_task`; Planner `_project_kb_task` | PASS: 3 finding probes về topic/above/weather, EN/VI prefix/suffix/reversed sources; conflict, residual caller dependency và don't denials không cấp quyền; quoted selectors/fixture P0 giữ đúng. Heuristic/corpus hữu hạn |
| P4-R06-compat / R06 | `tests/test_planner.py::test_p2_kb_projection_preserves_task_or_requires_clarification` (7 cases, không sửa test) | Shared projection → Planner | PASS: task/chi phí được giữ, context được cung cấp tương thích; task còn dựa vào caller hoặc quoted source selector bị từ chối |
| P4-R13-direct / R13 | `tests/test_agents.py::test_direct_analyst_rejects_caller_context_before_llm`; `test_analyst_rejects_unknown_evidence_ids` (2 cases); `test_confidence_rejects_nan_and_irrelevant_evidence`; `test_analyst_node_uses_structured_output_and_overrides_confidence` | `analyst.py::_validate_inputs`, `_validate_draft_quality`, `_calculate_confidence`, `analyst_node`; prompt `build_analyst_input` | PASS: direct API + builder từ chối non-empty/list sai kiểu ở OFF/ON, có/không KB; model không được gọi, error không có caller payload. conversation_1/invented ID không có trong KB bị từ chối; valid KB còn hoạt động |
| P4-flow / R06 + R13 | `tests/test_p1a_context_boundary.py::test_p4_both_source_projection_keeps_real_analyst_independent_of_caller`; `test_worker_input_views_do_not_receive_caller_context`; `tests/test_p1b_coordination_integrity.py::test_quote_only_differential_keeps_everything_outside_caller_identical` (3 cases, không sửa test) | Public workflow → real Research Guard/Analyst → analysis_result → final renderer | PASS: neutral/PI payload với forged role/source/verified không vào route/retrieval/Analyst prompt; analysis_result và các phần final ngoài caller_quote giống nhau; caller envelope vẫn origin_verified=False. Models/search stub, không đo model-level effectiveness |

### Artifact và kiểm chứng tối thiểu

Namespace: `artifacts/phase4_context/evaluator_v2/`.

- Chỉ sửa/bổ sung **3 module test hiện có**, không tạo test module mới. Tổng
  số testcase tăng **9** so với P3; test legacy cho phép caller evidence được
  đổi thành assertion từ chối đúng contract. Các test P2/P3/provenance khác
  được tái sử dụng, không nhân thêm ma trận mọi payload/agent/mode.
- `reproduction.xml`: 9 failed / 72 passed trước fix; `targeted.xml`: 81 passed;
  `targeted_verified.xml`: 88 passed, gồm 7 projection cases P2 có sẵn.
- `regression_final.xml`: **616 passed, 8 skipped**, 0 failure/error trên source
  cuối. Tám skip vẫn thuộc baseline CF đóng băng.
- `regression.xml` có 2 failed / 614 passed / 8 skipped: phát hiện thiếu cú pháp
  P2 và residual caller dependency, đã sửa bằng test sẵn có. `regression_verified.xml`
  đạt 616/8 trước bổ sung assertion apostrophe; giữ cả hai để truy vết, không
  dùng thay lượt nghiệm thu cuối. `apostrophe_probe_before.json` ghi scope sai
  trước fix don't; đây là deterministic probe, không phải model attack success.
- `source_before/`, `phase4_changes.diff`, `source_fingerprint.json` giữ snapshot
  đuôi .snapshot/diff/hash riêng P4, không trộn pre-existing workspace changes.
  `verification_commands.json` ghi lệnh/env/results; `finding_reference.txt` và
  `acceptance.json` ánh xạ mô tả gốc → fix → named tests → technical acceptance.
- `historical_verification.json`: **65 artifact P1/P2/P3 giữ nguyên hash**;
  không sửa evaluator hoặc viết lại bằng chứng lịch sử theo source P4.

### Giới hạn

- Source/domain parsing vẫn là grammar hữu hạn, chưa hiểu mọi cách diễn đạt;
  có thể hỏi lại hoặc phân loại chưa đúng với câu ngoài coverage. Scope không
  được suy từ caller payload; mặc định không cấp quyền sử dụng caller.
- Both/caller_only không hỗ trợ semantic analysis của caller; provenance chỉ
  ghi nguồn runtime, không chứng minh claim đúng hay source authenticity.
- Direct Analyst KB-only không phải public ingestion/authentication API. Các
  test model stub chứng minh input isolation/validation, không chứng minh
  model robustness hoặc ASR/FPR thực nghiệm. R06/R13 chưa model-level Validated.

## Phase 5 — Analysis-to-Execution / Approval and Final Provenance

Ngày nghiệm thu: 2026-10-05. **R03/R10/R14 = Fixed** sau regression kỹ thuật;
chưa model-level `Validated`. Giữ `evaluator_v2`, không chạy benchmark/API/model
thật. Phạm vi vẫn là PI và context spoofing ảnh hưởng downstream; không sửa
sandbox/process isolation hoặc refactor toàn project.

### Contract và thay đổi

- `execution_input` là public task data có schema `{tool_name, params}`, được
  xác nhận bằng `ExecutionRequest`/allowlist và snapshot JSON trước mọi model.
  Runtime giữ bản độc lập, không thể cập nhật từ worker state; public field
  được xóa trước Planner. Planner chỉ thấy bản đọc lại từ runtime. Action Gate
  bind cả tool lẫn toàn bộ params (records/metric/path/config/result/k).
  Source label hay self-digest của model không thay bản xác nhận này.
- `user_query` giữ vai trò mô tả/routing, `execution_input` là nguồn params
  có thẩm quyền theo contract. Không tự lấy records từ natural-language query,
  KB hay caller context. ON thiếu/mismatch bị deny; OFF observed/pass-through
  trong allowlist khi gate bật. Dataset path được bind theo path đã validate,
  không phải content hash của file. Runtime binding được xóa khi close.
- CLI thêm `--execution-input <file.json>` để tác vụ tool ON có đường nhập dữ
  liệu xác nhận. Harness multi-agent gửi RECORDS fixture trước planning và
  chuyển runtime đến Executor; không đổi assertions hay rubric để che lỗi.
- `build_workflow(approval_callback=...)` là cấu hình ứng dụng, không thuộc
  public input. Callback chỉ nhận write request đã vượt các check khác và
  phải trả bool, với immutable run ID/tool/digest/params JSON. Missing/False
  không cấp approval ON; exception/non-bool thành operational error cả OFF/ON,
  không gọi tool, không lộ callback exception. Bỏ state `execution_approval`
  khỏi runtime flow; cờ caller/model/worker không cấp quyền ghi. Không cache
  approval qua request/run. Callback không thay việc app xác thực người duyệt.
- Final chain render analysis qua kênh KB và execution qua kênh tool, có
  part ID/envelope riêng. Đối chiếu accepted payload với registry trước gắn
  provenance; giữ part guard và assembled guard, không thêm LLM tổng hợp.

### Bằng chứng theo finding

Các testcase dưới đây PASS trong `regression_final.xml`. `acceptance.json`
lưu đầy đủ tên có tham số, source/function và giới hạn chứng minh.

| Finding | Test name + file | Source/function | Kết quả và giới hạn |
| --- | --- | --- | --- |
| P5-R03 / R03 | `tests/test_action_gate.py::test_planner_self_digest_does_not_confirm_caller_task`; `tests/test_compiled_workflow.py::test_p5_analysis_cannot_replace_records_confirmed_before_planning` (OFF/ON); `test_p5_execution_input_is_frozen_and_invalid_input_stops_before_models`; `test_p5_cli_execution_input_reaches_protected_workflow`; `tests/test_action_gate_integration.py::test_executor_calls_action_gate_before_running_valid_tool_on` | `context_guard.py::bind_execution_input`, `context_boundary_node`; Planner `_build_execution_request`, `_prepare_execution_request`; `action_gate.py::evaluate_action_gate`; `executor.py::executor_node`; `main.py::main` | PASS: false,false candidate có self-digest hợp lệ bị chặn ON khi task xác nhận true,false; OFF observed; caller context/forged fields không thay task; path mutation và invalid schema không execute; valid task/CLI vẫn chạy. Model/KB/tool P5 đều stub, không phải model attack effectiveness |
| P5-R10 / R10 | `tests/test_compiled_workflow.py::test_compiled_graph_research_analysis_execute_keeps_both_outputs`; tái sử dụng part/assembled guard tests P1/P3 trong full regression | Planner `_synthesize_and_finalize`, `_finalize_answer`, `_finalize_parts` | PASS: giữ cả analysis và metric result; analysis part/envelope là KB, tool part/envelope là tool, IDs khác nhau. Provenance runtime không chứng minh kết luận hay metric đúng |
| P5-R14 / R14 | `tests/test_compiled_workflow.py::test_p5_public_write_uses_only_trusted_scoped_approval` (missing/deny/approve/non_bool/error/changed_request); `tests/test_action_gate_integration.py::test_executor_ignores_state_approval_and_requires_live_runtime_binding` | `workflow.py::build_workflow`, `WorkflowFacade.invoke`; `executor.py::executor_node`; `action_gate.py::ExecutionApprovalRequest` | PASS: chỉ valid request + trusted True gọi write stub; changed path không gọi callback; giả approval từ public/context/direct state không cấp quyền; closed runtime/error callback không execute. Chưa có UI approval hoặc authentication policy production |

### Artifact và mức test

Namespace: `artifacts/phase5_execution/evaluator_v2/`.

- Chỉ sửa/bổ sung **3 module test hiện có**, tăng **12 testcase** so với P4;
  không tạo module test mới. Một harness cũ được cập nhật public contract và
  runtime forwarding; assertions trong `test_multi_agent_coverage.py` giữ nguyên.
- `reproduction.xml`: 13 failed trước production fix. Ba failure tái hiện
  hành vi records substitution/nhãn sai; phần còn lại thể hiện contract mới
  chưa tồn tại. Đây không phải 13 attack successes hoặc ASR.
- `targeted.xml`: 59 passed sau fix đầu; có trước cập nhật harness và CLI.
- `regression.xml`: 4 failed / 623 passed / 8 skipped; bốn case ON của harness
  thiếu task binding/runtime forwarding. Giữ artifact để truy vết.
- `regression_final.xml`: **628 passed / 8 skipped**, 0 failure/error trên
  source nghiệm thu cuối. Tám skip vẫn thuộc baseline CF đóng băng. Không
  chạy model/API thật; P5 gọi tool stub, baseline tests có local metric tools.
- `acceptance.json`, `source_before/`, `phase5_changes.diff`,
  `source_fingerprint.json`, `verification_commands.json` giữ evidence theo ID,
  source/diff riêng P5 và lệnh tái hiện. `finding_reference.txt` giữ mô tả gốc.
- `historical_verification.json`: **89 artifact P1–P4 giữ nguyên hash**;
  không ghi đè evaluator hay evidence lịch sử theo source P5.

### Giới hạn

- Query-only tool ON phải cung cấp thêm task JSON; không dùng model extraction
  làm bản xác nhận. Save generated analysis chưa có result trong task input
  không được tự cấp quyền. Ràng buộc task không xác thực tính đúng của caller
  records, file contents hay source authenticity.
- Policy callback do ứng dụng triển khai; CLI chưa có UI duyệt ghi, callback
  phải tự xử lý danh tính/quyền người duyệt. Không dùng always-True callback.
- OFF cố ý không enforce context/approval policy; `action_gate_enabled=false`
  tắt các check context theo cấu hình. Allowlist/schema vẫn là baseline.
- Chưa đo độ bền model, ASR/FPR chính thức hoặc coverage ngữ nghĩa tổng quát;
  không chuyển ba finding sang `Validated` bằng unit/integration stubs.

## Phase 6 — Optimization / Equivalent Security Decisions

Ngày nghiệm thu: 2026-10-05. **Hoàn thành kiểm chứng kỹ thuật P6**. Phase này
không có finding R riêng trong backlog; trạng thái R01–R19 không thay đổi.
Giữ `evaluator_v2`, contract P5, rules/thresholds/fallback, provenance và guard
checkpoints. Không thay executor isolation/thread timeout hoặc gọi model/API.

### Đo baseline và lựa chọn thay đổi

- Corpus cố định gồm 5 user queries và 2 retrieval pools (8 clean/32 mixed
  documents), chạy OFF/ON: **14 guard cases**, có content/metadata lặp.
  Mỗi guard có 3 warmup và 25 sample đo bằng `perf_counter_ns`; cProfile đếm
  số lần thực sự vào body normalization/detector và YAML parser.
- Baseline Input Guard median 1,88–2,51 ms; load settings 1,84–1,85 ms.
  Pool 32 documents có 408 detector body calls và 2.480 canonicalization
  body calls. Đây là bằng chứng để chọn cả reuse scan lẫn cache parse YAML.
- Cache detector chỉ tồn tại trong một guard call, dùng ContextVar để tách
  scope, key chứa function/text/context, tối đa 256 entry. Nested guard mở
  scope mới; normal return/exception đều clear/reset. Không cache risk score,
  policy hoặc combine fields; cached rule lists được copy khi trả cho caller.
- Cache YAML là private validated template theo content + selected mode,
  tối đa 8 entry; mỗi load đọc file và trả deep copy. Không dựa riêng vào mtime
  hoặc file size; giữ behavior lỗi schema/file missing, tránh stale policy.

### Bằng chứng tối thiểu

Các test dưới đây PASS trong `regression_final.xml`; full result comparison
giữa source trước/sau nằm trong `comparison.json` và hai artifact measurement.

| Evidence | Test name + file | Source/function | Kết quả |
| --- | --- | --- | --- |
| P6-SCAN | `tests/test_patterns.py::test_p6_detection_reuse_keeps_context_lists_and_scope_independent`; `tests/test_security_guards.py::test_p6_guard_reuse_preserves_full_results_and_reduces_normalization` | `patterns.py::_reuse_detection`, `_memoize_detection`, `canonicalize_text`, `detect_injection_patterns`; Input/Retrieval Guard | PASS: user/retrieval context không lẫn, list mutation không làm sai cache, nested exception được cleanup; cached/uncached guard giữ full values/events/rules/scores/actions ở OFF/ON và giảm normalization calls |
| P6-CONFIG | `tests/test_security_guards.py::test_p6_settings_cache_tracks_contents_mode_and_caller_mutation` | `config.py::_parse_security_settings`, `load_security_settings` | PASS: parse reuse, mode selection, caller mutation isolation; edit giữ cùng size/mtime vẫn cập nhật; invalid policy/file missing vẫn lỗi |
| P6-EQUIVALENCE | `measure_guards.py --stage before/after`, `before.json`, `after.json`, `comparison.json` | Guard thật trước/sau P6; runner/source/corpus hashes | PASS: **14/14 full GuardResult dictionaries bằng nhau**, gồm input/accepted documents và mọi event; cùng runner và corpus hash. Đây là bounded deterministic equivalence, không phải model-level validation |

### Số đo cục bộ

Các giá trị dưới đây là median tại mode ON, không gồm import/model/network/tool.
Settings load dùng 25 sample; median phản ánh warm cache, không đo cold startup.

| Case | Trước (ms) | Sau (ms) | Work trước → sau |
| --- | ---: | ---: | --- |
| Input medium command | 1,8995 | 0,2639 | Canonicalization 3 → 1; detector body 2 → 1 |
| Retrieval clean, 8 documents | 10,2944 | 2,2365 | Canonicalization 672 → 21; detector body 104 → 37 |
| Retrieval mixed, 32 documents | 37,3224 | 10,0137 | Canonicalization 2.480 → 80; detector body 408 → 144 |
| Settings load | 1,8544 | 0,1355 | Warm parse được reuse; file vẫn được đọc |

### Artifact và nghiệm thu

Namespace: `artifacts/phase6_optimization/evaluator_v2/`.

- Chỉ sửa **4 file production** và thêm **3 testcase trong 2 module test có
  sẵn**. Không tạo module test mới; unit tests không phụ thuộc artifact P6.
- `targeted.xml`: **94 passed**; có trước bổ sung cache reset để test config
  độc lập với thứ tự suite. `regression_final.xml`: **631 passed / 8 skipped**,
  0 failure/error trên source cuối; tám skip baseline CF giữ nguyên.
- `before.json`/`after.json` lưu full deterministic results, tất cả timing
  samples, work counts, source/corpus/runner hashes và Python/platform.
  `measure_guards.py` là runner measurement, không phải test module, không
  đọc `.env` hay gọi provider/KB/tools. Runner từ chối ghi đè artifact cũ.
- `acceptance.json`, `source_fingerprint.json`, `source_before/`,
  `phase6_changes.diff`, `verification_commands.json` ghi named test evidence,
  source/hash và lệnh tái hiện. `historical_verification.json` xác nhận
  **114 artifact P1–P5 giữ nguyên hash**; không sửa rubric hoặc evidence cũ.

### Giới hạn

- Corpus tổng hợp nhỏ, có text/metadata lặp, đo trước/sau tuần tự trên cùng
  máy. Median guard nhanh hơn không suy thành mọi workload hay toàn workflow
  nhanh hơn; chưa đo cold-cache overhead, memory peak hoặc model/network time.
- Giới hạn 256 entry không phải giới hạn byte-size của raw text. Cache giữ
  scan data trong lúc guard chạy; cleanup đã kiểm tra, không claim RAM giảm.
- Chỉ cache pure scans với rules tĩnh và config content; config default/code
  thay đổi cần lifecycle reload process phù hợp. Không giữ decision, caller
  authorization hoặc approval trong cache. Không thêm timing thresholds gây
  flaky tests và không đổi policy để đạt tốc độ.
- Chưa tạo ASR/FPR hoặc nâng bất kỳ finding nào thành model-level `Validated`.

## Phase 7 — Cleanup / Reproducibility

Ngày nghiệm thu: 2026-10-05. **R15 và R17 Fixed sau kiểm chứng kỹ thuật**.
Giữ `evaluator_v2`, policy và checkpoint P1–P6; không chạy model/API thật,
không phát sinh ASR/FPR mới hoặc chuyển finding sang `Validated`.

### Thay đổi giới hạn

- R15: sao chép nguyên byte query/payload JSON, baseline manifest và ZIP
  source đóng băng sang `tests/fixtures/coordinator_flaw/`; cập nhật ba test
  consumer và manual harness. Archive giữ SHA-256 gốc và **100 entry**;
  manifest giữ provenance/đường dẫn capture lịch sử, có README giải thích.
  Output path và các gate kiểm soát quyền chạy smoke không đổi.
- R17: `scripts_test_phase7.py::run_acceptance` kiểm tra bước graph
  **4/6/4/2** có context boundary. OOS thực tế giữ `current_agent=None`;
  không đổi worker expectation theo suy đoán. Case tool gửi `execution_input`
  trước Planner và phải có `status=success`; case analysis phải có envelope
  Analyst được chấp nhận ở kênh KB. Import script không load dotenv/KB/model.
- Thêm `scripts_test_offline.py` làm runner cho suite hiện có; chỉ thêm
  **1 testcase trong `tests/test_compiled_workflow.py`**, không tạo test module.
  Dời load dotenv của acceptance thật vào `main`, sửa docstring workflow đã
  lỗi thời và README về scope, hai roadmap, execution/approval, offline/export.
- Giữ `spikes/` vì test registry còn import; giữ tám test baseline đóng băng
  và evidence lịch sử. Không có bằng chứng đủ để xóa các file này; không
  refactor production hoặc gom/xóa test hàng loạt.

### Bằng chứng theo finding

| ID | Test name + file | Source/function | Kết quả |
| --- | --- | --- | --- |
| P7-R15 | `tests/test_context_guard.py::test_query_fixture_matches_deterministic_scope_contract` | `classify_scope_query`, fixture reader | PASS: mọi query trong fixture khớp scope contract |
| P7-R15 | `tests/test_p1b_coordination_integrity.py::test_p42_preflight_builds_frozen_dry_run_plans_without_api_authority` | `manual_test_coordinator_flaw.py::build_preflight_manifest`, `validate_baseline_archive` | PASS: fixture/manifest/archive hợp lệ, preflight không có execution authorization/API access |
| P7-R15 | `tests/test_p1b_coordination_integrity.py::test_p42_preflight_manifest_writer_is_metadata_only`; `test_p42_preflight_cli_refuses_execution_without_dry_run` | `write_preflight_manifest`, `main` | PASS: không ghi secret/payload; CLI không tự chạy thực nghiệm |
| P7-R17 | `tests/test_compiled_workflow.py::test_p7_acceptance_script_matches_compiled_routes_and_confirmed_tool` | `scripts_test_phase7.py::run_acceptance`, `build_workflow().invoke` | PASS: 4 route × OFF/ON với guard thật, provider/search/tool stubs; nhận analysis KB, tool 0.5, OOS không thêm worker call |
| P7-R15/R17 | Toàn suite `tests/` qua `scripts_test_offline.py` trong clean export | Source bundle 123 file, không có artifact lịch sử tại thời điểm bắt đầu | **632 passed / 8 skipped**, 0 failure/error; mọi hash source trước/sau bằng manifest |

### Artifact và tái hiện

Namespace: `artifacts/phase7_reproducibility/evaluator_v2/`.

- `targeted_verified.xml`: **5 passed**. Các lần kiểm tra trung gian có lỗi
  assertion theo tên field `ExecutionResult.tool` và params chuẩn hóa `k=None`
  đã sửa; giữ XML trung gian để truy vết, không dùng làm evidence nghiệm thu.
- `regression_clean_export.xml` và `.log`: toàn suite trong thư mục giải nén
  tạm riêng, sử dụng dependency environment đang có, dotenv bị tắt và
  PYTHONPATH không trỏ về workspace. Tám skip thuộc baseline CF đóng băng.
- `source_export.zip`, `source_export_manifest.json`,
  `regression_source_manifest.json`, `clean_export_verification.json` lưu
  bundle/hash và điều kiện chạy. Export không có `.env*`, `.git`, `.venv`,
  cache, vector DB, trace cũ hoặc artifact lịch sử. Source/fixture ZIP cần
  thiết được đóng gói; không giữ folder export trong project để tránh pytest
  thu thập hai bản test. Fingerprint cuối chỉ cập nhật backlog/docs sau test;
  các file kỹ thuật giữ nguyên byte đã được kiểm chứng.
- `acceptance.json`, `source_fingerprint.json`, `fixture_copy.json`,
  `source_before/`, `phase7_changes.diff`, `verification_commands.json`,
  `environment.json` lưu mapping ID/test/function, hash, lệnh và dependencies.
  `verify_export.py` là evidence runner, không phải test module; lần chạy verify
  từ chối ghi đè regression đã có.
- `historical_verification.json`: **136 artifact P1–P6 giữ nguyên hash**.
  `version_control_manifest.json` ghi source/fixture còn untracked, không tự
  stage/commit. Các fixture mới không bị `.gitignore` che.

### Giới hạn nghiệm thu

- Đây là **clean source export**, chưa phải fresh Git checkout: nhiều file
  cần thiết còn untracked. Bàn giao qua Git phải đưa đầy đủ source/fixtures
  trong manifest vào version control trước khi xác nhận fresh checkout.
- Test dùng Python/dependencies đã cài, không chứng minh install từ đầu trên
  môi trường mới. `requirements.txt` vẫn chưa pin toàn bộ dependency graph;
  `environment.json` lưu môi trường đã chạy để đối chiếu.
- Runner offline vô hiệu dotenv và pytest plugin tự nạp; stubs nằm trong test,
  không tự bảo đảm test mới bất kỳ sẽ không gọi mạng. Không dùng kết quả này
  để khẳng định model-level attack effectiveness hay chấm lại artifact cũ.
