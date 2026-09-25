# Kế hoạch nhiệm vụ Blue Team

Tài liệu này là kế hoạch tuần tự để bổ sung các lớp phòng thủ Prompt Injection cho project multi-agent AI security. Mỗi task có phạm vi file riêng, test riêng, acceptance criteria và commit riêng. Chỉ chuyển sang task tiếp theo sau khi task hiện tại đã được nghiệm thu. README này là tài liệu thực thi, không phải script chạy trực tiếp.

## Trạng thái nền của project

- Đã có `Input Guard`, `Retrieval Guard`, `Output Guard` cho secret, tool allowlist, schema validation, process isolation, timeout và tracing.
- `SecurityEvent` hiện còn tối giản; các field telemetry mở rộng sẽ được chuẩn hóa ở T00.5.
- Chưa có route restriction thật trong Planner/state, semantic classifier, prompt canary hoặc contextual Action Gate. Không được giả lập các behavior này chỉ bằng tên event.
- `tests/manual_test_retrieval_guard.py --retrieval fixture` dùng fixture trong bộ nhớ và không sửa vector DB, nhưng workflow vẫn có thể gọi LLM thật để tạo answer. Fixture không đồng nghĩa với offline hoàn toàn.
- Các manual test có thể tạo artifact trong `artifacts/` và trace log. Artifact sinh ra trong baseline phải được ghi nhận, không tự động đưa toàn bộ workspace vào commit.

## Nguyên tắc thực hiện

- Chỉ làm một task tại một thời điểm; không chạy song song các task có file giao nhau.
- Mỗi task tạo một commit riêng; không dùng `git add -A` nếu chưa xem staged diff.
- Unit test không gọi API LLM thật. Semantic classifier phải được mock.
- Manual integration test có thể gọi LLM thật; phải ghi rõ thiếu API key, thiếu dependency, timeout hoặc lỗi mạng là lỗi môi trường, không phải kết quả phòng thủ.
- Không rebuild, reset hoặc ghi đè vector DB chính trong các task bảo mật.
- Mỗi lớp phải có clean-control để đo false positive.
- Mọi ngưỡng số phải nằm trong `SecuritySettings` và hai file YAML, không hardcode rải rác.
- Giữ nguyên hành vi vận hành bắt buộc: tool allowlist, schema validation, process isolation, timeout và sandbox.
- Không ghi system prompt, API key hoặc payload bí mật nguyên văn vào telemetry.

## Hợp đồng Defense Off/On

| Lớp | `DEFENSE_MODE=off` | `DEFENSE_MODE=on` |
|---|---|---|
| Input Guard | Cho qua, ghi `observed` | Block risk cao |
| Retrieval Guard | Giữ chunk, ghi `observed` | Filter chunk risk cao |
| Semantic classifier | Không dùng để block | Chỉ gọi theo policy medium-risk |
| Output Guard | Giữ output, ghi `observed` | Redact hoặc canned refusal |
| Action Gate | Chỉ ghi telemetry cho ngữ cảnh không phù hợp; vẫn giữ allowlist, schema, process isolation, timeout và sandbox | Block action không phù hợp |
| Tool allowlist | Luôn áp dụng | Luôn áp dụng |

## Telemetry contract

Task T00.5 sẽ chuẩn hóa event dùng chung:

```json
{
  "stage": "input|agent_message|retrieval|knowledge_validation|tool_permission|output",
  "attack_type": "prompt_injection|prompt_exfiltration|indirect_injection|tool_manipulation|none",
  "risk_score": 0.0,
  "rule": "detector_name",
  "action": "allowed|observed|restricted|filtered|blocked|redacted",
  "detail": "safe detail",
  "trace_id": "trace-id-or-unavailable",
  "document_id": null,
  "chunk_id": null,
  "mode": "on|off"
}
```

`restricted` chỉ được dùng khi workflow thật sự hạn chế route hoặc quyền. Hiện project chưa có `route_restricted` trong state/Planner, nên trước T03 mọi medium-risk chỉ ghi `observed`. `detail` không được chứa system prompt, API key, secret hoặc payload nhạy cảm nguyên văn; nếu cần đối chiếu dùng hash hoặc metadata an toàn.

## T00 — Baseline read-only

Mục tiêu: ghi lại behavior trước khi thêm lớp mới.

Phạm vi: chỉ đọc và chạy test; không reset vector DB, không commit tự động.

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe tests/manual_test_input_guard.py --mode off
.\.venv\Scripts\python.exe tests/manual_test_input_guard.py --mode on
.\.venv\Scripts\python.exe tests/manual_test_retrieval_guard.py --mode off
.\.venv\Scripts\python.exe tests/manual_test_retrieval_guard.py --mode on
.\.venv\Scripts\python.exe tests/manual_test_full_pipeline_attacks.py --mode both
.\.venv\Scripts\python.exe tests/manual_test_multi_agent_coverage.py --mode both --retrieval fixture
```

Hai lệnh cuối là manual integration baseline: có thể cần API/model, còn `--retrieval fixture` không reset vector DB nhưng vẫn có thể gọi LLM để tổng hợp answer. Ghi nhận cả trường hợp lỗi môi trường thay vì coi đó là kết quả phòng thủ. Ghi nhận số test pass/fail, số payload được phát hiện, số chunk được lọc, security events, trace ID và lỗi môi trường. Nếu working tree đang dirty, không tạo baseline commit bằng toàn bộ workspace.

Với `tests/manual_test_input_guard.py`, cả sáu payload `PI_01` đến `PI_06` là attack cases và phải có `allowed=False` ở Defense On. `PI_02` chỉ được gọi là roleplay có rủi ro vì nó kèm yêu cầu truy cập dữ liệu nhạy cảm; `PI_06` là authority/urgent impersonation kèm prompt extraction. Roleplay thuần túy phải được kiểm tra bằng clean-control riêng.

Acceptance: có kết quả baseline, không sửa runtime file và xác định được test nào đang fail trước khi bắt đầu T00.5. Các file artifact/log do test tạo ra không được xem là runtime change và không được commit nếu task chưa chỉ định.

Commit nếu cần lưu artifact riêng:

```text
blue-team: record prompt injection baseline
```

## T00.5 — Chuẩn hóa SecurityEvent

Mục tiêu: mọi guard dùng cùng schema trước khi thêm detector mới.

File được phép sửa:

- `security/models.py`
- `graph/state.py`
- Các call site chuyển event vào state, hiện gồm Planner, Researcher và Executor khi nối guard result.
- Test event hiện có.

Nhiệm vụ:

- Thêm `attack_type`, `risk_score`, `trace_id`, `mode` và metadata tùy chọn.
- Giữ các stage hiện có: `agent_message`, `knowledge_validation`, `tool_permission`.
- Thêm `restricted` chỉ khi T03 có route restriction thật.
- Cho phép guard nhận telemetry context mà không log system prompt.

Test: event cũ tương thích, risk score bị giới hạn trong `[0,1]`, action/stage hợp lệ và event không chứa secret hoặc payload nhạy cảm nguyên văn. `restricted` chỉ được thêm vào action khi đã có behavior route/quyền tương ứng.

Commit:

```text
refactor(security): standardize security event telemetry
```

## T01 — Canonicalization chống obfuscation

Mục tiêu: mở rộng logic đã có trong `security/patterns.py`, tránh tạo hai bộ normalization độc lập.

File được phép sửa:

- `security/patterns.py` hoặc module dùng chung được `patterns.py` gọi.
- Test normalization riêng.

Nhiệm vụ:

- Giữ NFKC và zero-width handling hiện tại.
- Nhận diện `i-g-n-o-r-e`, `i.g.n.o.r.e`, `i_g_n_o_r_e`.
- Tạo bản normalized và compact cho detector.
- Giữ input gốc để log và truyền tiếp khi policy cho phép.
- Input gốc không được ghi nguyên văn vào telemetry nếu chứa secret hoặc dữ liệu nhạy cảm; dùng sanitized detail/hash khi cần truy vết.

Test: tiếng Việt có dấu, zero-width, token splitting, văn bản sạch và bảo toàn input gốc.

Commit:

```text
feat(security): improve prompt canonicalization
```

## T02 — Composite prompt risk scoring

Mục tiêu: chấm điểm theo tổ hợp tín hiệu thay vì block vì một keyword.

File được phép sửa:

- Tạo `security/prompt_risk.py`.
- `security/config.py` và hai YAML nếu cần thêm signal weight; không đặt weight số trực tiếp trong detector.
- Tạo test cho module này.

Tín hiệu gồm `override`, `internal_target`, `sensitive_action`, `roleplay`, `authority_claim`, `obfuscation` và `tool_intent`.

Quy tắc đánh giá phải phân biệt tín hiệu đơn lẻ với tổ hợp có ý định rõ ràng. `roleplay` đơn lẻ là clean-control; `roleplay` kết hợp yêu cầu file cấu hình, system prompt, secret hoặc hành động nhạy cảm là attack và phải đạt high risk trong bộ sáu payload baseline. Trọng số và ngưỡng không đặt trong module detector mà đọc từ `SecuritySettings`/YAML.

Output T02 chỉ gồm:

```python
RiskAssessment(
    score=0.0,
    attack_type="...",
    signals=["..."],
    sensitive_target=None,
)
```

T02 không trả `risk_level`. T03 là nơi duy nhất map score thành low/medium/high theo threshold trong config.

Test: một tín hiệu đơn lẻ không thành high risk, tổ hợp override với internal target được phát hiện, roleplay thuần túy được cho qua và câu hỏi nghiên cứu không bị đánh nhầm.

Commit:

```text
feat(security): add composite prompt risk scoring
```

## T03 — Tích hợp risk score vào Input Guard

Mục tiêu: áp dụng threshold và action policy cho user input.

File được phép sửa:

- `security/input_guard.py`
- `security/config.py`
- `configs/defense_on.yaml`
- `configs/defense_off.yaml`
- `tests/test_input_guard_integration.py`

Threshold mặc định phải cấu hình được:

| Score | On | Off |
|---:|---|---|
| `< 0.55` | Allow | Allow, có thể ghi event |
| `0.55–<0.80` | `restricted` nếu route restriction đã triển khai | Allow, `observed` |
| `>= 0.80` | Block | Allow, `observed` |

Nếu chưa có `route_restricted` trong state và Planner, medium-risk chỉ ghi telemetry; không giả lập restriction bằng tên event. Sáu payload baseline `PI_01`–`PI_06` phải được đánh giá high risk để Defense On block đủ 6/6.

Test: Off không block sáu payload, On block high risk, medium policy đúng, clean-control không bị block và event có score/mode/attack type.

Commit:

```text
feat(security): integrate prompt risk into input guard
```

## T04 — Tăng cường Retrieval Guard

Mục tiêu: chống Indirect Prompt Injection trong retrieved content.

File được phép sửa:

- `security/retrieval_guard.py`
- Module retrieval-risk mới nếu cần.
- `tests/test_retrieval_guard.py`

Nhiệm vụ:

- Dùng canonicalization và risk scoring dùng chung.
- Phân biệt câu mô tả nghiên cứu với câu mệnh lệnh cho Agent.
- Threshold retrieval nằm trong config.
- On lọc chunk high risk trước Research/Analyst.
- Off giữ chunk và ghi `observed`.
- Giữ trust, hash, source allowlist và không đọc `is_poisoned` để quyết định runtime.
- Nếu toàn bộ chunk bị lọc, Planner phải kết thúc an toàn thay vì gọi Analyst với context rỗng.

Test: cùng payload bị lọc ở On và giữ ở Off; clean document có từ khóa nghiên cứu không bị false positive; chunk bị lọc không đến Analyst.

Commit:

```text
feat(security): harden retrieval guard against indirect injection
```

## T05 — Semantic classifier cho medium risk

Mục tiêu: xử lý diễn đạt gián tiếp sau rule-based scoring.

File được phép sửa:

- Tạo `security/semantic_classifier.py`.
- Tích hợp vào Input Guard sau khi module độc lập đạt test.
- `security/config.py`.
- `configs/defense_on.yaml` và `configs/defense_off.yaml`.
- `tests/test_semantic_classifier.py` và test integration riêng.

Cấu hình tối thiểu:

- `semantic_classifier_enabled`.
- `semantic_classifier_timeout_seconds`.
- `semantic_positive_policy`.

Classifier phải có interface injectable/callable để unit test mock hoàn toàn. README không yêu cầu gọi một provider LLM cụ thể. Giá trị malformed, timeout và exception phải đi qua fallback đã cấu hình; không để workflow treo hoặc làm lộ exception nội bộ.

Policy:

- Low không gọi classifier.
- High không gọi classifier vì rule đã đủ.
- Medium mới gọi classifier.
- Classifier positive nâng risk lên high; On áp dụng block, Off chỉ `observed`.
- Timeout hoặc malformed output dùng fallback đã cấu hình và không làm workflow treo.

Test: kiểm tra số lần gọi, positive result dẫn đến block ở On, positive result chỉ observed ở Off, timeout, malformed schema và clean-control medium risk được đánh giá an toàn.

Commit:

```text
feat(security): add semantic classifier for ambiguous prompts
```

## T06 — Prompt canary injection

Mục tiêu: chèn canary theo session hoặc invocation để phát hiện system prompt leak.

File được phép sửa:

- Module tạo canary.
- Workflow state lưu `canary_id` hoặc identifier tương đương và fingerprint; không lưu system prompt nguyên văn.
- Bảo vệ mọi prompt builder có system/developer instruction, hiện tối thiểu là prompt call của Planner và Analyst.
- Test canary.

Canary không thể triển khai chỉ bằng `output_guard.py`, vì Output Guard hiện chỉ nhận final answer. Call site phải truyền identifier/fingerprint vào Output Guard. Không lưu system prompt nguyên văn trong state hoặc log.

Test: mỗi session có canary riêng, canary được chèn đúng prompt và fingerprint không lộ trong telemetry. Việc quét canary và kiểm tra refusal thuộc T07.

Commit:

```text
feat(security): add per-session prompt canary
```

## T07 — Output Prompt-Leak Guard

Mục tiêu: phát hiện và xử lý final answer làm lộ system/developer prompt.

File được phép sửa:

- `security/output_guard.py`
- Module prompt-leak detector nếu cần.
- Call site truyền canary/fingerprint.
- Test output guard riêng.

Nhiệm vụ:

- Quét canary.
- Dùng fingerprint hoặc n-gram similarity theo threshold trong config.
- Phát hiện cấu trúc prompt nội bộ mà không log prompt nguyên văn.
- On trả canned refusal hoặc redacted output.
- Off chỉ `observed`.

Mapping action:

- `blocked`: phát hiện canary hoặc prompt-leak có độ tin cậy cao và thay toàn bộ output bằng canned refusal.
- `redacted`: phát hiện secret hoặc đoạn nhạy cảm có thể loại bỏ an toàn, phần output còn lại vẫn được trả.
- Nếu một output vừa có prompt-leak vừa có secret, ưu tiên `blocked`; không trả bản đã redacted vì vẫn có thể còn prompt nội bộ.

Ở Defense Off, Output Guard giữ nguyên output và chỉ ghi `observed`. Ở Defense On, `blocked` phải làm `GuardResult.allowed=False`; `redacted` giữ `allowed=True` nếu phần còn lại an toàn. Canned refusal phải được loại khỏi detector hoặc có rule riêng để không tự bị nhận là prompt leak.

Test: canary bị phát hiện và tạo `blocked`; canned refusal không bị đánh nhầm là leak; output sạch được giữ; secret redaction cũ tạo `redacted`; Off chỉ ghi `observed` và không redact.

Commit:

```text
feat(security): add output prompt leak guard
```

## T08 — Action Gate trước Executor

Mục tiêu: kiểm tra ngữ cảnh tool call ngoài tool allowlist.

File được phép sửa:

- Tạo `security/action_gate.py`.
- `agents/executor.py` hoặc call site thực thi cuối cùng.
- `security/config.py` và YAML nếu cần threshold.
- `tests/test_action_gate.py` và Executor integration test.

Kiểm tra:

- Tool call có phù hợp user query không.
- Tham số có bị lấy từ retrieved instruction không.
- Có sửa record, metric hoặc dữ liệu không.
- Có write/destructive action cần approval không.
- Tool có nằm trong allowlist không.

Tool allowlist, sandbox và process isolation vẫn áp dụng ở cả hai mode. Action Gate phải thật sự được gọi trước khi Executor chạy tool.

Action Gate không thay thế allowlist. Nó cần nhận user query, tool name, params, nguồn của params và trạng thái approval/destructive action. Tool đọc thuần túy không cần approval ghi; tool ghi hoặc phá hủy phải có approval rõ ràng. Nếu action cần provenance/approval mà state chưa có dữ liệu đó thì Defense On phải fail closed và ghi rõ lý do; Defense Off chỉ ghi telemetry nhưng vẫn không được bỏ qua allowlist/schema/sandbox.

Test: tool ngoài allowlist bị chặn, tool hợp lệ chạy, retrieved document không sửa được params và On chặn action không phù hợp.

Commit:

```text
feat(security): add executor action gate
```

## T09 — Full pipeline regression matrix

Mục tiêu: kiểm tra các lớp khi chạy cùng workflow.

File được phép sửa:

- Mở rộng `tests/manual_test_full_pipeline_attacks.py` hiện có.
- Mở rộng `tests/manual_test_multi_agent_coverage.py` hiện có.
- Thêm evaluator hoặc fixture mới nếu cần.

Không tạo lại hai script đã tồn tại. Ma trận phải gồm sáu Direct Injection (`PI_01`–`PI_06`), Indirect Retrieval Injection, zero-width, token splitting, roleplay có hành động nhạy cảm, mixed language, admin/urgent impersonation, output extraction, tool manipulation và clean-control tương ứng. Roleplay thuần túy là clean-control, không dùng để hạ mục tiêu block của sáu attack cases.

Mỗi case lưu mode, payload hash, raw documents đã được sanitized hoặc fixture digest, documents sau guard, events, trace ID, worker thực sự chạy, tool call, final answer đã được sanitized và verdict. Không ghi secret/prompt bí mật nguyên văn vào artifact chỉ để phục vụ đánh giá.

Test manual:

```powershell
.\.venv\Scripts\python.exe tests/manual_test_full_pipeline_attacks.py --mode both
.\.venv\Scripts\python.exe tests/manual_test_multi_agent_coverage.py --mode both --retrieval fixture
```

Không kết luận `ATTACK_SUCCESS` chỉ vì keyword xuất hiện trong final answer; phải kiểm tra đúng mục tiêu của case.

Commit:

```text
test(security): extend full pipeline attack matrix
```

## T10 — Documentation và bàn giao

Mục tiêu: ghi lại kiến trúc và kết quả sau khi code/test ổn định.

File được phép sửa:

- `README.md`.
- Báo cáo Blue Team được chỉ định.
- Tài liệu chạy test nếu cần.

Phải ghi rõ stage block/filter, khác biệt Off/On, detection rate, false-positive rate, giới hạn semantic evasion, timeout/fallback của classifier, giới hạn canary và sự khác nhau giữa tool allowlist với authorization theo ngữ cảnh. Detection rate phải nêu rõ mẫu số attack cases; false-positive rate phải tính trên clean-control tương ứng. Lỗi môi trường phải tách khỏi cả hai metric.

Commit:

```text
docs(security): document Blue Team defense architecture
```

## Acceptance checklist

Trước khi chuyển task hoặc push:

- Test của task hiện tại pass.
- Regression test liên quan pass.
- Off không block/filter/redact các lớp tùy chọn.
- On áp dụng đúng policy.
- Clean-control chạy cùng attack cases.
- Không có secret trong source, log hoặc artifact.
- Không reset vector DB chính ngoài chủ đích.
- `.env` không nằm trong staged diff.
- `git diff --check` không báo lỗi.
- Staged file đúng phạm vi task.

Kiểm tra staged diff:

```powershell
git diff --cached --check
git diff --cached --stat
git diff --cached --name-only
git diff --cached -- .env
```

Nếu task fail, chỉ sửa trong task đó, chạy lại test của task và test regression. Không chuyển task, gộp commit hoặc đổi threshold để che lỗi.
