# Frozen Coordinator Flaw fixtures

Ba file được sao chép nguyên byte từ `artifacts/p0_coordinator_flaw/`
trong P7 để tests/preflight không phụ thuộc output bị Git ignore:

- `query_payload_fixtures.json`: query, payload và expected scope.
- `baseline_manifest.json`: provenance của baseline đóng băng.
- `baseline-source-e8bc16a7-20261002.zip`: source baseline, 100 entry,
  SHA-256 `7c645075b3d3de31ac656de16c6537548de3f55247895c97d6b9f0bdce37a21c`.

Manifest giữ nguyên đường dẫn lịch sử tại thời điểm capture; harness hiện tại
resolve file qua thư mục này. Đây là fixture cần version control, không phải
output benchmark mới hoặc source thay thế workflow hiện tại. Baseline tests
đã đóng băng vẫn skip; validation archive/hash và preflight hiện hành vẫn chạy.

Không sửa nội dung archive/manifest để cập nhật baseline. Không thay đổi các
output path hoặc authorization gate của smoke harness khi chuyển fixture.
