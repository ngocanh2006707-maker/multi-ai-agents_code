# Trợ lý nghiên cứu bảo mật AI đa tác tử

## Tình trạng hiện tại

Đây là prototype nghiên cứu về bảo mật cho AI Agent và hệ thống đa tác tử, chạy qua CLI bằng LangGraph theo kiến trúc Centralized Orchestrator.

### Chức năng hiện có

- Planner định tuyến công việc tới Researcher, Analyst hoặc Executor; các agent worker trả kết quả về Planner.
- Knowledge Base hỗ trợ truy xuất tài liệu và metadata nguồn.
- Chế độ Defense ON có các kiểm soát cho input, context, retrieval, output và tool execution.
- Chế độ Defense OFF là baseline cố ý không bảo vệ, dùng để so sánh trong thí nghiệm.

### Phạm vi và giới hạn

Project tập trung vào Prompt Injection và User-Originated Coordinator Flaw qua `conversation_context`. Các guard là biện pháp phòng thủ của prototype, không bảo đảm chặn mọi tấn công hoặc chứng minh model-level robustness.

Ứng dụng hiện có giao diện CLI qua `main.py`; `app.py` chưa triển khai giao diện web hoặc API. Defense mode mặc định là `off` nếu tiến trình không nhận `DEFENSE_MODE=on`.
