"""Tests for secret storage + run-scoped env injection + key validation.

Uses the in-memory backend so the real OS keychain is never touched.
"""

import os

from pcrm.secrets import (
    SecretStore, MemoryBackend, known_secret_names, injected_env, validate_key,
)


def _store():
    return SecretStore(backend=MemoryBackend())


def test_set_get_delete_exists():
    s = _store()
    assert not s.exists("SHODAN_API_KEY")
    s.set("SHODAN_API_KEY", "abc123")
    assert s.get("SHODAN_API_KEY") == "abc123"
    assert s.exists("SHODAN_API_KEY")
    s.delete("SHODAN_API_KEY")
    assert not s.exists("SHODAN_API_KEY")
    s.delete("SHODAN_API_KEY")          # deleting a missing key is a no-op


def test_status_reports_set_without_values():
    s = _store()
    s.set("VT_API_KEY", "secret-value")
    st = {d["name"]: d for d in s.status(["VT_API_KEY", "HIBP_API_KEY"])}
    assert st["VT_API_KEY"]["set"] is True
    assert st["HIBP_API_KEY"]["set"] is False
    assert "value" not in st["VT_API_KEY"]      # values are never exposed


def test_known_secret_names_covers_keyed_collectors_and_slack():
    names = known_secret_names()
    assert {"SHODAN_API_KEY", "VT_API_KEY", "HIBP_API_KEY",
            "SLACK_WEBHOOK_URL"} <= set(names)
    # keyless collectors (crt.sh etc.) contribute no key name
    assert "" not in names


def test_injected_env_sets_and_clears():
    s = _store()
    s.set("SHODAN_API_KEY", "k1")
    os.environ.pop("SHODAN_API_KEY", None)
    with injected_env(s, ["SHODAN_API_KEY"]):
        assert os.environ["SHODAN_API_KEY"] == "k1"
    assert "SHODAN_API_KEY" not in os.environ        # cleared on exit


def test_injected_env_restores_prior_value():
    s = _store()
    s.set("VT_API_KEY", "new")
    os.environ["VT_API_KEY"] = "orig"
    try:
        with injected_env(s, ["VT_API_KEY"]):
            assert os.environ["VT_API_KEY"] == "new"
        assert os.environ["VT_API_KEY"] == "orig"    # restored, not deleted
    finally:
        os.environ.pop("VT_API_KEY", None)


def test_validate_key_slack_format():
    assert validate_key("SLACK_WEBHOOK_URL",
                        "https://hooks.slack.com/services/T/B/x")["ok"] is True
    assert validate_key("SLACK_WEBHOOK_URL", "http://evil.test/x")["ok"] is False


def test_validate_key_missing_then_format_only():
    assert validate_key("HIBP_API_KEY", "")["ok"] is False          # no value
    r = validate_key("HIBP_API_KEY", "some-key")
    assert r["ok"] is True and "format only" in r["detail"]          # no live probe


def test_validate_key_unknown_name():
    assert validate_key("NOPE_KEY", "x")["ok"] is False
