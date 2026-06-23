"""API-key storage in the OS keychain + run-scoped environment injection.

Keys (Shodan, Censys, HIBP, VT, Mallory, Leak-Lookup, and the Slack webhook)
live in the OS keychain via `keyring` (macOS Keychain / Windows Credential
Manager) — never in plaintext on disk and never echoed back. At run time they're
loaded into the process environment for the run's duration only, so collectors
keep reading `os.environ[KEY_ENV]` unchanged.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterable

SERVICE = "securitysight"


class MemoryBackend:
    """In-memory `keyring`-shaped backend (used by tests; never touches the OS)."""

    def __init__(self):
        self._d: dict[tuple[str, str], str] = {}

    def get_password(self, service, name):
        return self._d.get((service, name))

    def set_password(self, service, name, value):
        self._d[(service, name)] = value

    def delete_password(self, service, name):
        self._d.pop((service, name), None)


class SecretStore:
    """Thin wrapper over a keyring-shaped backend. Defaults to the real OS keychain."""

    def __init__(self, backend=None, service: str = SERVICE):
        self.service = service
        self._backend = backend

    @property
    def backend(self):
        if self._backend is None:
            import keyring  # lazy: tests using MemoryBackend don't need it installed
            self._backend = keyring
        return self._backend

    def get(self, name: str) -> str | None:
        return self.backend.get_password(self.service, name)

    def set(self, name: str, value: str) -> None:
        self.backend.set_password(self.service, name, value)

    def delete(self, name: str) -> None:
        try:
            self.backend.delete_password(self.service, name)
        except Exception:  # noqa: BLE001 - deleting a missing key is a no-op
            pass

    def exists(self, name: str) -> bool:
        return bool(self.get(name))

    def status(self, names: Iterable[str] | None = None) -> list[dict]:
        """Names + whether each is set — values are never returned."""
        names = list(names) if names is not None else known_secret_names()
        return [{"name": n, "set": self.exists(n)} for n in names]


def known_secret_names() -> list[str]:
    """Every secret the app manages: each collector's KEY_ENV + the Slack webhook."""
    from .registry import ALL
    names: list[str] = []
    for cls in ALL:
        if cls.KEY_ENV and cls.KEY_ENV not in names:
            names.append(cls.KEY_ENV)
    names.append("SLACK_WEBHOOK_URL")
    return names


@contextmanager
def injected_env(store: SecretStore, names: Iterable[str] | None = None):
    """Load stored secrets into os.environ for the duration of the block, then
    restore the previous environment exactly."""
    names = list(names) if names is not None else known_secret_names()
    saved: dict[str, str | None] = {}
    try:
        for n in names:
            v = store.get(n)
            if v is not None:
                saved[n] = os.environ.get(n)
                os.environ[n] = v
        yield
    finally:
        for n, old in saved.items():
            if old is None:
                os.environ.pop(n, None)
            else:
                os.environ[n] = old


def validate_key(name: str, value: str | None = None) -> dict:
    """Validate one secret by env name (used by the key-setup wizard).

    The Slack webhook is format-checked; collector keys delegate to the
    collector's `validate()` (cheap live probe where available, else format-only).
    """
    if name == "SLACK_WEBHOOK_URL":
        ok = bool(value and value.startswith("https://hooks.slack.com/"))
        return {"ok": ok, "detail": "looks like a Slack incoming-webhook URL"
                if ok else "does not look like a Slack webhook URL"}
    from .registry import ALL
    for cls in ALL:
        if cls.KEY_ENV == name:
            return cls().validate(value)
    return {"ok": False, "detail": f"unknown secret: {name}"}
