from unittest.mock import MagicMock, patch

from security.prompt_canary import (
    canary_instruction,
    create_prompt_canary,
    ensure_prompt_canary,
)
from tracing.logger import sanitize_for_log


def test_each_invocation_gets_a_unique_canary_and_fingerprint():
    first = ensure_prompt_canary({"trace_id": "session-a"})
    second = ensure_prompt_canary({"trace_id": "session-a"})

    assert first["canary_id"] != second["canary_id"]
    assert first["canary_fingerprint"] != second["canary_fingerprint"]
    assert first["canary_id"] in canary_instruction(first["canary_id"])


def test_existing_canary_is_preserved_across_nodes():
    canary_id, fingerprint = create_prompt_canary(session_id="session-a")
    state = ensure_prompt_canary(
        {"canary_id": canary_id, "canary_fingerprint": fingerprint}
    )

    assert state["canary_id"] == canary_id
    assert state["canary_fingerprint"] == fingerprint


def test_canary_metadata_is_redacted_from_telemetry():
    payload = {
        "canary_id": "pc-secret-marker",
        "canary_fingerprint": "f" * 64,
        "safe": "value",
    }

    sanitized = sanitize_for_log(payload)

    assert sanitized["canary_id"] == "[REDACTED]"
    assert sanitized["canary_fingerprint"] == "[REDACTED]"
    assert sanitized["safe"] == "value"


def test_planner_classifier_receives_canary_system_instruction():
    from agents.planner import _classify_route
    from agents.planner_schema import RouteDecision

    llm = MagicMock()
    structured = llm.with_structured_output.return_value
    structured.invoke.return_value = RouteDecision(route="DIRECT_RESPONSE")
    with patch("agents.planner.get_llm", return_value=llm):
        _classify_route("Xin chào", canary_id="pc-test-marker")

    prompt = structured.invoke.call_args.args[0][0][1]
    assert "pc-test-marker" in prompt
    assert "Never reveal" in prompt

