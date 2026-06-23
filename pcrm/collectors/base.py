"""Collector plugin contract.

A collector takes the watchlist and returns Findings. Every collector declares
its metadata (name, the env var holding its API key, mode, cadence) so the
registry can render the `--list` table and the runner can skip ones whose key
is missing.

Subclass rules:
  * set the class attributes (NAME, KEY_ENV, CADENCE, ...)
  * implement collect(self, companies) -> list[Finding]
  * be PASSIVE. These query third-party indexes and public feeds. Nothing here
    touches the target companies' infrastructure directly.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Company, Finding


class BaseCollector:
    NAME: str = "base"
    # Env var name that must be set for this collector to run. "" = no key needed.
    KEY_ENV: str = ""
    MODE: str = "passive"          # passive | active  (this project is passive-only)
    CADENCE: str = "daily"         # daily | weekly  (informational scheduling hint)
    STATUS: str = "live"           # live | stub
    TIMEOUT: int = 20

    def __init__(self):
        self.session = None  # lazily created requests.Session

    # ---- metadata helpers -------------------------------------------------
    @property
    def api_key(self) -> str | None:
        return os.environ.get(self.KEY_ENV) if self.KEY_ENV else None

    @property
    def ready(self) -> bool:
        """True if the collector can actually run (key present when required)."""
        if self.STATUS == "stub":
            return False
        if self.KEY_ENV and not self.api_key:
            return False
        return True

    def _http(self):
        if self.session is None:
            import requests
            self.session = requests.Session()
            self.session.headers.update({"User-Agent": "portco-risk-monitor/0.1"})
        return self.session

    # ---- the one method subclasses implement ------------------------------
    def collect(self, companies: list["Company"]) -> list["Finding"]:
        raise NotImplementedError

    # ---- key validation (used by the GUI key-setup wizard) ----------------
    def validate(self, value: str | None = None) -> dict:
        """Check whether this collector's key is usable. Returns
        {"ok": bool, "detail": str}. Uses `value` if given (e.g. a key the user
        just typed, before it's saved), else the configured env key.

        Default is presence/format only; collectors that can verify cheaply
        override `_validate_live`."""
        if not self.KEY_ENV:
            return {"ok": True, "detail": "no key required"}
        key = value if value is not None else self.api_key
        if not key:
            return {"ok": False, "detail": f"{self.KEY_ENV} is not set"}
        live = self._validate_live(key)
        if live is not None:
            return live
        return {"ok": True, "detail": "key present (format only; not verified live)"}

    def _validate_live(self, key: str) -> dict | None:
        """Override to verify a key against the provider with a cheap call.
        Return {"ok": bool, "detail": str}, or None to fall back to format-only."""
        return None
