"""Core data structures for the portfolio risk monitor.

Two objects flow through the whole system:

  Company  - something on your watchlist (a portfolio company, a vendor, your
             own org). Carries the identifiers collectors pivot on.
  Finding  - one observation about one company from one source. This is the
             atom the data lake stores and the dashboard triages.

Findings are intentionally source-agnostic: a ransomware mention, an exposed
database, a KEV match and a breached credential are all just Findings with a
different `kind` and `detail`. That uniformity is what lets the scoring engine
correlate across sources.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Company:
    """An entity on the watchlist that collectors pivot on."""

    name: str
    domains: list[str] = field(default_factory=list)
    cidrs: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    # 1.0 = normal. Bump for crown-jewel companies so their findings float up.
    criticality: float = 1.0
    tags: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Company":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})

    def search_terms(self) -> list[str]:
        """Everything a name/keyword-based source should look for."""
        terms = [self.name, *self.aliases, *self.domains]
        # de-dupe while preserving order
        seen, out = set(), []
        for t in terms:
            t = (t or "").strip()
            if t and t.lower() not in seen:
                seen.add(t.lower())
                out.append(t)
        return out


# Severity bands. Findings carry a numeric severity (0-100); these are the
# labels and cut points the dashboard and Slack alerter use.
SEVERITY_BANDS = [
    (90, "critical"),
    (70, "high"),
    (40, "medium"),
    (15, "low"),
    (0, "info"),
]


def severity_label(score: float) -> str:
    for cut, label in SEVERITY_BANDS:
        if score >= cut:
            return label
    return "info"


@dataclass
class Finding:
    """One observation about one company from one source."""

    company: str            # Company.name this relates to
    source: str             # collector name, e.g. "shodan"
    kind: str               # taxonomy, e.g. "exposed_service", "ransomware_mention"
    title: str              # human-readable one-liner
    detail: dict[str, Any] = field(default_factory=dict)
    evidence_url: str | None = None
    # base_severity is what the collector asserts on its own; the scoring engine
    # may raise it via correlation. Kept separate so we can show both.
    base_severity: float = 0.0
    observed_at: str = field(default_factory=utcnow_iso)

    # ---- fields populated downstream (lake / scoring) ----
    first_seen: str | None = None
    last_seen: str | None = None
    score: float = 0.0
    score_reasons: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        """Stable identity used for dedup and 'is this new today?' diffing.

        Deliberately excludes timestamps and scores: the same exposed service
        seen on two days is the *same* finding, just with a later last_seen.
        """
        basis = json.dumps(
            {
                "company": self.company,
                "source": self.source,
                "kind": self.kind,
                # detail can be noisy; the collector marks the stable bits via
                # an "_id" key when it wants a custom identity. Fall back to title.
                "key": self.detail.get("_id", self.title),
            },
            sort_keys=True,
        )
        return hashlib.sha1(basis.encode()).hexdigest()[:16]

    @property
    def severity(self) -> str:
        return severity_label(self.score or self.base_severity)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        d["severity"] = self.severity
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})
