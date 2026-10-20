"""Điều chỉnh đề cương thực tập ba chương cho khớp với project hiện tại.

DOCX nguồn được giữ nguyên. Script này chỉnh trực tiếp WordprocessingML để
bảo toàn thiết lập trang, style, đánh số và metadata của tài liệu.
"""
from __future__ import annotations

import copy
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET


SOURCE = Path(
    r"C:\Users\PC-Admin\Downloads\De_cuong_3_chuong_Prompt_Injection_Data_Poisoning.docx"
)
OUTPUT = Path("De_cuong_3_chuong_da_dieu_chinh_theo_project.docx")

W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
W = "{" + W_NS + "}"
ET.register_namespace("w", W_NS)

DEFENSE_TABLE_TEMPLATE: ET.Element | None = None


REPLACEMENTS = {
    "1.2.5. Memory": "1.2.5. Conversation Context, Shared State và giới hạn của Memory",
    "1.3.6. Shared Memory và Shared Resources": "1.3.6. Shared State và Shared Resources",
    "bộ nhớ riêng và bộ nhớ dùng chung;": (
        "conversation context và shared state của workflow; persistent memory không thuộc phạm vi thực nghiệm hiện tại;"
    ),
    "memory read/write flow;": "conversation-context/shared-state flow;",
    "bộ nhớ của agent;": "conversation context và shared state của agent;",
    "tính toàn vẹn của Knowledge Base và memory;": "tính toàn vẹn của Knowledge Base, conversation context và shared state;",
    "Agent – Memory;": "Agent – Conversation Context/Shared State;",
    "Memory Attacks;": "Memory Attacks (chỉ trình bày ở mức lý thuyết và hướng mở rộng);",
    "1.10. Nguyên tắc và cơ chế phòng thủ": "1.10. Nguyên tắc phòng thủ ở mức lý thuyết",
    "1.13. Tổng kết chương": "1.11. Tổng kết chương",
    "2.2.5. Đặc tả giao diện Retrieval, Memory và Tool Calling": (
        "2.2.5. Đặc tả giao diện Retrieval, Conversation Context/Shared State và Tool Calling"
    ),
    "2.3.4. BGE-M3 cho Embedding và BGE-reranker-v2-m3 cho Reranking": (
        "2.3.4. BGE-M3 cho Embedding và Trust-aware Reranking"
    ),
    "2.4.4. Memory Layer": "2.4.4. Conversation Context và Shared State",
    "2.8. Phân tích vị trí triển khai phòng thủ": "2.8. Kiến trúc phòng thủ nhiều lớp và vị trí triển khai",
    "2.9.3. Message/Communication Guard": (
        "2.9.3. Kiểm soát dữ liệu truyền qua Shared State giữa các Agent"
    ),
    "2.12.2. Đóng gói môi trường bằng Docker": "2.12.2. Môi trường Python, virtual environment và dependency",
    "2.12.3. Kiểm thử tự động và CI/CD": "2.12.3. Kiểm thử tự động bằng pytest và các script kiểm thử",
    "2.13. Tổng kết chương": "2.14. Tổng kết chương",
    "3.2.2. Prompt Injection Scenario do Red Team cung cấp": (
        "3.2.2. Prompt Injection Scenario do Red Team cung cấp"
    ),
    "3.2.3. Data Poisoning Scenario do Red Team cung cấp": (
        "3.2.3. Data Poisoning Scenario do Red Team cung cấp"
    ),
    "3.6. Kết quả với Context/Input Guard": "3.6. Kết quả với Context/Input Guard",
    "3.7. Kết quả với Knowledge/Retrieval Guard": "3.7. Kết quả với Knowledge/Retrieval Guard",
    "3.8. Kết quả với Message/Communication Guard": (
        "3.8. Kết quả quan sát sự lan truyền qua Shared State giữa các Agent"
    ),
    "3.9. Kết quả với Tool/Action Authorization": (
        "3.9. Kết quả với Output Guard và Tool/Action Authorization"
    ),
}


def text_of(node: ET.Element) -> str:
    return "".join(item.text or "" for item in node.findall(".//" + W + "t"))


def paragraphs(root: ET.Element) -> list[ET.Element]:
    return root.findall(".//" + W + "body/" + W + "p")


def set_text(paragraph: ET.Element, value: str) -> None:
    text_nodes = paragraph.findall(".//" + W + "t")
    if not text_nodes:
        run = ET.SubElement(paragraph, W + "r")
        target = ET.SubElement(run, W + "t")
    else:
        target = text_nodes[0]
        for extra in text_nodes[1:]:
            extra.text = ""
    target.text = value


def find_paragraph(root: ET.Element, exact_text: str) -> ET.Element:
    for paragraph in paragraphs(root):
        if text_of(paragraph).strip() == exact_text:
            return paragraph
    raise KeyError(f"Không tìm thấy đoạn: {exact_text}")


def insert_after(body: ET.Element, reference: ET.Element, new_node: ET.Element) -> ET.Element:
    index = list(body).index(reference)
    body.insert(index + 1, new_node)
    return new_node


def clone_with_text(template: ET.Element, value: str) -> ET.Element:
    node = copy.deepcopy(template)
    set_text(node, value)
    return node


def collapse_chapter_one_defense_block(root: ET.Element) -> None:
    """Giữ phần lý thuyết phòng thủ ngắn gọn và chuyển chi tiết triển khai sang chương 2."""
    body = root.find(".//" + W + "body")
    assert body is not None
    heading = find_paragraph(root, "1.10. Nguyên tắc phòng thủ ở mức lý thuyết")
    first_detail = find_paragraph(root, "1.10.1. Kiểm tra dữ liệu không đáng tin cậy")
    chapter_summary = find_paragraph(root, "1.11. Tổng kết chương")

    set_text(
        first_detail,
        "Trình bày ở mức nguyên tắc các lớp defense-in-depth gồm kiểm tra dữ liệu không đáng tin cậy, "
        "tách biệt chỉ thị và dữ liệu, provenance, least privilege, kiểm soát shared state, sandboxing "
        "và monitoring. Thiết kế, trạng thái triển khai và cách đánh giá từng cơ chế được trình bày tại "
        "Chương 2 và Chương 3. Memory trong project hiện chỉ giới hạn ở conversation context/shared state; "
        "persistent memory không thuộc phạm vi thực nghiệm.",
    )

    global DEFENSE_TABLE_TEMPLATE
    children = list(body)
    start = children.index(first_detail) + 1
    end = children.index(chapter_summary)
    for child in children[start:end]:
        if child.tag == W + "tbl":
            DEFENSE_TABLE_TEMPLATE = copy.deepcopy(child)
        body.remove(child)

    # Giữ phần chuyển tiếp rõ ràng từ lý thuyết phòng thủ sang tóm tắt chương.
    assert list(body).index(heading) < list(body).index(chapter_summary)


def enrich_chapter_two(root: ET.Element) -> None:
    body = root.find(".//" + W + "body")
    assert body is not None

    # Bổ sung lựa chọn LLM thực tế còn thiếu trong phần công nghệ ban đầu.
    pydantic_heading = find_paragraph(root, "2.3.5. Pydantic cho schema và kiểm tra dữ liệu giữa các Agent")
    stack_comparison = find_paragraph(root, "2.3.6. So sánh lựa chọn và lý do phù hợp với testbed")
    set_text(pydantic_heading, "2.3.6. Pydantic cho schema và kiểm tra dữ liệu giữa các Agent")
    set_text(stack_comparison, "2.3.7. So sánh lựa chọn và lý do phù hợp với testbed")
    gemini = clone_with_text(
        pydantic_heading,
        "2.3.5. Google Gemini cho mô hình ngôn ngữ lớn theo cấu hình hiện tại",
    )
    insert_after(body, find_paragraph(root, "2.3.4. BGE-M3 cho Embedding và Trust-aware Reranking"), gemini)

    # Tái sử dụng bảng lớp phòng thủ ban đầu nhưng đặt vào Chương 2, nơi
    # kiến trúc phòng thủ cụ thể được thiết kế.
    if DEFENSE_TABLE_TEMPLATE is not None:
        defense_heading = find_paragraph(root, "2.8. Kiến trúc phòng thủ nhiều lớp và vị trí triển khai")
        insert_after(body, defense_heading, copy.deepcopy(DEFENSE_TABLE_TEMPLATE))

    # Bổ sung Output Guard vì module này tồn tại trong security/output_guard.py.
    tool_guard = find_paragraph(root, "2.9.4. Tool/Action Authorization")
    output_guard = clone_with_text(tool_guard, "2.9.5. Output Guard và kiểm soát rò rỉ dữ liệu nhạy cảm")
    insert_after(body, tool_guard, output_guard)

    # Bổ sung bảng ánh xạ trạng thái triển khai trước phần tóm tắt chương.
    summary = find_paragraph(root, "2.14. Tổng kết chương")
    heading_template = find_paragraph(root, "2.12. Môi trường triển khai, đóng gói và khả năng tái lập")
    subheading_template = find_paragraph(root, "2.12.1. Môi trường localhost và cấu hình hiện tại")
    body_template = find_paragraph(root, "Red Team không sửa mã nguồn hệ thống, cơ chế phòng thủ hoặc log nếu không thuộc quyền đã xác định trước.")

    nodes = [
        clone_with_text(heading_template, "2.13. Đối chiếu Threat–Defense và trạng thái triển khai"),
        clone_with_text(subheading_template, "2.13.1. Các cơ chế đã có trong project"),
        clone_with_text(
            body_template,
            "Input Guard, Retrieval Guard, Output Guard, Executor tool allowlist, schema validation, tracing và security events.",
        ),
        clone_with_text(subheading_template, "2.13.2. Các cơ chế triển khai một phần hoặc thuộc hướng mở rộng"),
        clone_with_text(
            body_template,
            "Standalone Message/Communication Guard, persistent memory protection, Docker và CI/CD chưa được xem là kết quả triển khai hiện tại.",
        ),
        clone_with_text(subheading_template, "2.13.3. Ma trận Threat–Defense và điểm can thiệp"),
        clone_with_text(
            body_template,
            "Ánh xạ Prompt Injection và Data Poisoning tới các lớp ngăn chặn, phát hiện, giới hạn tác động và truy vết, đồng thời ghi rõ trạng thái implemented, partial hoặc future work.",
        ),
    ]
    reference = list(body)[list(body).index(summary) - 1]
    for node in nodes:
        reference = insert_after(body, reference, node)


def add_scope_notes(root: ET.Element) -> None:
    body = root.find(".//" + W + "body")
    assert body is not None
    normal_template = find_paragraph(
        root,
        "Red Team không sửa mã nguồn hệ thống, cơ chế phòng thủ hoặc log nếu không thuộc quyền đã xác định trước.",
    )

    # Làm rõ phạm vi bao phủ Prompt Injection hiện tại.
    prompt_effect = find_paragraph(
        root,
        "ghi nhận tác động lên câu trả lời, thông điệp giữa agent và tool call nếu có.",
    )
    pi_note = clone_with_text(
        normal_template,
        "Trạng thái hiện tại: bộ cases đã có ca lành tính và Direct Prompt Injection. Indirect Prompt Injection "
        "được guard_retrieval hỗ trợ phát hiện ở nội dung retrieval nhưng cần bổ sung test case và evidence; "
        "Cross-Agent Prompt Injection chỉ đánh giá khi có cơ chế quan sát phù hợp.",
    )
    insert_after(body, prompt_effect, pi_note)

    # Làm rõ mức độ sẵn sàng cho Data Poisoning hiện tại.
    data_effect = find_paragraph(root, "đánh giá mức độ làm sai lệch câu trả lời hoặc quyết định.")
    dp_note = clone_with_text(
        normal_template,
        "Trạng thái hiện tại: data/poisoned và experiments/data_poisoning/results chưa có dataset/kết quả thực nghiệm "
        "hoàn chỉnh. Chỉ trình bày kết quả sau khi Red Team tạo poison dataset, chạy clean/poisoned baseline và lưu evidence.",
    )
    insert_after(body, data_effect, dp_note)

    # Giới hạn các khẳng định về bộ nhớ trong phần phân tích lan truyền.
    memory_effect = find_paragraph(root, "khả năng ảnh hưởng tới memory;")
    set_text(
        memory_effect,
        "khả năng ảnh hưởng tới conversation context/shared state; không đánh giá persistent memory;",
    )

    # Bổ sung ghi chú rõ ràng về mức độ sẵn sàng thí nghiệm trong Chương 3.
    attack_variants = find_paragraph(root, "3.2.4. Các biến thể và mức độ khó của tấn công")
    readiness_note = clone_with_text(
        normal_template,
        "Phạm vi bắt buộc gồm clean case, Direct Prompt Injection và Data Poisoning khi đã có poison dataset. "
        "Indirect/Cross-Agent Prompt Injection chỉ đưa vào bảng kết quả khi đã có case, ground truth và trace tương ứng.",
    )
    insert_after(body, attack_variants, readiness_note)

    # Làm cho kỳ vọng kết quả theo từng chế độ khớp với điểm thực thi thực tế.
    context_heading = find_paragraph(root, "3.6. Kết quả với Context/Input Guard")
    context_items = []
    current = list(body).index(context_heading) + 1
    for child in list(body)[current:]:
        if child.tag == W + "p":
            value = text_of(child).strip()
            if value.startswith("3.7."):
                break
            if value:
                context_items.append(child)
    if len(context_items) >= 3:
        set_text(context_items[0], "Direct Prompt Injection: detection và blocking;")
        set_text(context_items[1], "False Positive trên benign input;")
        set_text(context_items[2], "Benign Utility và độ trễ của Input Guard.")

    retrieval_heading = find_paragraph(root, "3.7. Kết quả với Knowledge/Retrieval Guard")
    retrieval_items = []
    current = list(body).index(retrieval_heading) + 1
    for child in list(body)[current:]:
        if child.tag == W + "p":
            value = text_of(child).strip()
            if value.startswith("3.8."):
                break
            if value:
                retrieval_items.append(child)
    if len(retrieval_items) >= 3:
        set_text(retrieval_items[0], "Indirect Prompt Injection trong nội dung retrieval;")
        set_text(retrieval_items[1], "Data Poisoning: poison retrieval, filtering và answer influence;")
        set_text(retrieval_items[2], "Benign Utility và False Positive của Retrieval Guard.")

    shared_heading = find_paragraph(root, "3.8. Kết quả quan sát sự lan truyền qua Shared State giữa các Agent")
    shared_items = []
    current = list(body).index(shared_heading) + 1
    for child in list(body)[current:]:
        if child.tag == W + "p":
            value = text_of(child).strip()
            if value.startswith("3.9."):
                break
            if value:
                shared_items.append(child)
    if len(shared_items) >= 3:
        set_text(shared_items[0], "Propagation metadata và security events nếu có;")
        set_text(shared_items[1], "không suy diễn thành một Message Guard độc lập nếu chưa có module thực thi;")
        set_text(shared_items[2], "khả năng truy vết qua LangGraph shared state và tracing.")

    output_heading = find_paragraph(root, "3.9. Kết quả với Output Guard và Tool/Action Authorization")
    output_items = []
    current = list(body).index(output_heading) + 1
    for child in list(body)[current:]:
        if child.tag == W + "p":
            value = text_of(child).strip()
            if value.startswith("3.10."):
                break
            if value:
                output_items.append(child)
    if len(output_items) >= 3:
        set_text(output_items[0], "Phát hiện/redaction dữ liệu nhạy cảm ở final output;")
        set_text(output_items[1], "tool allowlist, denied tool call và tool-misuse outcome;")
        set_text(output_items[2], "Benign Utility và ảnh hưởng tới tác vụ hợp lệ.")


def apply_replacements(root: ET.Element) -> None:
    for original, replacement in REPLACEMENTS.items():
        paragraph = find_paragraph(root, original)
        set_text(paragraph, replacement)


def main() -> None:
    if not SOURCE.exists():
        raise SystemExit(f"Không tìm thấy file nguồn: {SOURCE}")

    with zipfile.ZipFile(SOURCE, "r") as zin:
        root = ET.fromstring(zin.read("word/document.xml"))
        apply_replacements(root)
        collapse_chapter_one_defense_block(root)
        enrich_chapter_two(root)
        add_scope_notes(root)
        new_xml = ET.tostring(root, encoding="utf-8", xml_declaration=True)

        with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                payload = new_xml if item.filename == "word/document.xml" else zin.read(item.filename)
                zout.writestr(item, payload)

    print(OUTPUT.resolve())


if __name__ == "__main__":
    main()
