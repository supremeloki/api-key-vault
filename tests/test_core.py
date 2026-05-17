import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from key_vault import (
    KeyInvalidError,
    KeyNotFoundError,
    KeyVault,
    fingerprint_key,
    looks_like_api_key,
    mask_key,
)


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        self.now += 1.0
        return self.now


@pytest.fixture
def vault(tmp_path):
    return KeyVault(store_path=tmp_path / "vault.json", clock=FakeClock())


def test_mask_hides_middle():
    masked = mask_key("sk-abcdefghijklmnopqrstuvwxyz")
    assert masked.startswith("sk-a")
    assert masked.endswith("wxyz")
    assert "*" in masked


def test_fingerprint_deterministic_and_short():
    fp = fingerprint_key("sk-test-value-12345678901234567890")
    again = fingerprint_key("sk-test-value-12345678901234567890")
    assert fp == again and len(fp) == 16


def test_set_returns_masked_entry(vault):
    entry = vault.set("openai", "sk-abcdefghijklmnopqrstuvwxyz")
    assert entry.masked_value != "sk-abcdefghijklmnopqrstuvwxyz"
    assert len(entry.fingerprint) == 16


def test_get_roundtrips_secret(vault):
    vault.set("anthropic", "hf_" + "a" * 35)
    assert vault.get("anthropic") == "hf_" + "a" * 35


def test_get_unknown_raises(vault):
    with pytest.raises(KeyNotFoundError):
        vault.get("ghost-service")


def test_env_fallback(monkeypatch):
    import os

    os.environ["VAULT_KEY_FALLBACK_SVC"] = "ghp_" + "b" * 36
    try:
        fresh = KeyVault(store_path=Path(__import__("tempfile").gettempdir()) / "nv.json",
                         clock=FakeClock())
        assert fresh.get("fallback-svc").startswith("ghp_")
    finally:
        del os.environ["VAULT_KEY_FALLBACK_SVC"]


def test_empty_values_rejected(vault):
    with pytest.raises(KeyInvalidError):
        vault.set("openai", "   ")
    with pytest.raises(KeyInvalidError):
        vault.set("  ", "sk-something")


def test_usage_tracked(vault):
    vault.set("deepseek", "sk-" + "z" * 30)
    vault.get("deepseek")
    vault.get("deepseek")
    report = vault.audit_report()
    assert report[0]["use_count"] == 2
    assert report[0]["ever_used"] is True


def test_persists_across_instances(tmp_path):
    path = tmp_path / "persist.json"
    first = KeyVault(store_path=path, clock=FakeClock())
    first.set("mistral", "sk-" + "m" * 32)
    second = KeyVault(store_path=path, clock=FakeClock())
    assert "mistral" in second.list_services()
    audit = second.audit_report()
    assert audit[0]["masked"] == mask_key("sk-" + "m" * 32)


def test_verify_fingerprint(vault):
    real = "sk-" + "v" * 28
    vault.set("together", real)
    assert vault.verify_fingerprint("together", real)
    assert not vault.verify_fingerprint("together", "sk-wrong-value-here-1234")


def test_delete_removes_service(vault):
    vault.set("xai", "sk-" + "x" * 30)
    assert vault.delete("xai") is True
    assert "xai" not in vault.list_services()
    assert vault.delete("xai") is False


def test_scan_environment_detects_keys(monkeypatch):
    import os

