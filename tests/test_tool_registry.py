import pytest

from tools import registry


EXPECTED_TOOLS = (
    "calculate_metrics",
    "calculate_metrics_from_dataset",
    "read_dataset",
    "run_security_test",
    "save_test_result",
)


def test_registry_contains_exact_configured_tools():
    assert registry.list_allowed_tools() == EXPECTED_TOOLS
    assert all(callable(registry.get_tool(name)) for name in EXPECTED_TOOLS)


def test_unregistered_and_prohibited_tools_are_denied():
    assert not registry.is_allowed("shell")
    with pytest.raises(registry.ToolNotAllowedError):
        registry.get_tool("shell")
    with pytest.raises(registry.ToolNotAllowedError):
        registry.register_tool("shell", lambda: None)
    with pytest.raises(registry.ToolNotAllowedError):
        registry.register_tool("unconfigured_tool", lambda: None)


def test_registry_is_frozen_after_bootstrap():
    with pytest.raises(registry.RegistryFrozenError):
        registry.register_tool("read_dataset", lambda: None)
    with pytest.raises(TypeError):
        registry._TOOL_REGISTRY["shell"] = lambda: None


def test_register_rejects_invalid_name_and_callable():
    with pytest.raises(ValueError):
        registry.register_tool("   ", lambda: None)
    with pytest.raises(TypeError):
        registry.register_tool("read_dataset", "not callable")
