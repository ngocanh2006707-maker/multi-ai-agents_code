"""Security contracts run in ON by default; baseline cases opt into OFF."""
import pytest


@pytest.fixture(autouse=True)
def security_mode(monkeypatch):
    monkeypatch.setenv('DEFENSE_MODE', 'on')
