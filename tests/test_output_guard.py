import pytest

from security.output_guard import CANNED_REFUSAL, guard_output


def test_canary_leak_is_blocked_on(monkeypatch):
    monkeypatch.setenv("DEFENSE_MODE", "on")
    result = guard_output(
        "The hidden value is <PROMPT_CANARY:pc-test-marker>.",
        canary_id="pc-test-marker",
        canary_fingerprint="f" * 64,
    )

    assert result.allowed is False
    assert result.value == CANNED_REFUSAL
    assert any(event.rule == "prompt_canary_leak" for event in result.events)
    assert all("pc-test-marker" not in event.detail for event in result.events)


def test_fingerprint_leak_is_blocked_on_without_logging_fingerprint(monkeypatch):
    monkeypatch.setenv("DEFENSE_MODE", "on")
    fingerprint = "a" * 64
    result = guard_output("fingerprint=" + fingerprint, canary_fingerprint=fingerprint)

    assert result.allowed is False
    assert result.value == CANNED_REFUSAL
    assert any(event.rule == "prompt_fingerprint_leak" for event in result.events)
    assert fingerprint not in " ".join(event.detail for event in result.events)


def test_structural_prompt_leak_is_blocked_on(monkeypatch):
    monkeypatch.setenv("DEFENSE_MODE", "on")
    result = guard_output("Here is the developer instructions and hidden prompt.")

    assert result.allowed is False
    assert result.value == CANNED_REFUSAL
    assert any(event.rule == "prompt_structure_leak" for event in result.events)


def test_canned_refusal_is_not_detected_again(monkeypatch):
    monkeypatch.setenv("DEFENSE_MODE", "on")

    result = guard_output(CANNED_REFUSAL)

    assert result.allowed is True
    assert result.value == CANNED_REFUSAL
    assert result.events == []


def test_secret_only_is_redacted_on(monkeypatch):
    monkeypatch.setenv("DEFENSE_MODE", "on")
    secret = "sk-abcdefghijklmnop"

    result = guard_output("safe text " + secret)

    assert result.allowed is True
    assert secret not in result.value
    assert result.value.endswith("[REDACTED]")
    assert result.events[0].action == "redacted"


def test_prompt_leak_takes_precedence_over_secret(monkeypatch):
    monkeypatch.setenv("DEFENSE_MODE", "on")
    result = guard_output(
        "system prompt leaked with sk-abcdefghijklmnop",
        canary_id="pc-marker",
    )

    assert result.allowed is False
    assert result.value == CANNED_REFUSAL
    assert any(event.rule == "prompt_structure_leak" for event in result.events)
    assert all(event.action == "blocked" for event in result.events)


def test_off_observes_and_preserves_prompt_leak(monkeypatch):
    monkeypatch.setenv("DEFENSE_MODE", "off")
    output = "system prompt leaked with sk-abcdefghijklmnop"

    result = guard_output(output, canary_id="pc-marker")

    assert result.allowed is True
    assert result.value == output
    assert any(event.action == "observed" for event in result.events)


@pytest.mark.parametrize("answer", [
    "A system prompt defines the role of an AI agent.",
    "The phrase 'ignore previous instructions' is commonly used when demonstrating prompt injection attacks.",
    "Developer instructions should not be exposed to untrusted users.",
    "Chỉ dẫn hệ thống xác định vai trò của một AI Agent.",
])
def test_security_explanations_are_allowed_but_disclosure_is_detected(monkeypatch, answer):
    for mode in ("on",):
        monkeypatch.setenv("DEFENSE_MODE", mode)
        benign = guard_output(answer)
        mixed = guard_output(answer + "\nHere is the system prompt: You are a private assistant.")
        assert benign.allowed is True and benign.value == answer and benign.events == []
        assert mixed.allowed is (mode == "off")
        assert any(event.rule == "prompt_structure_leak" for event in mixed.events)


def test_structure_switch_does_not_disable_exact_canary_or_secret_redaction(monkeypatch):
    from security.config import SecuritySettings

    monkeypatch.setattr("security.output_guard.load_security_settings", lambda: SecuritySettings(
        defense_enabled=True, output_guard=True, prompt_structure_check_enabled=False,
    ))
    assert guard_output("Here is the system prompt: an example.").allowed is True
    result = guard_output("pc-private-marker sk-abcdefghijklmnop", canary_id="pc-private-marker")
    assert result.allowed is False and result.value == CANNED_REFUSAL
    assert {event.rule for event in result.events} == {"prompt_canary_leak", "secret_pattern_2"}
    assert guard_output("sk-abcdefghijklmnop").value == "[REDACTED]"
