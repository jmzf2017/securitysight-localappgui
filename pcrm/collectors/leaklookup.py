"""Leak-Lookup — credential leak search by domain. Needs LEAKLOOKUP_API_KEY.

Searches the Leak-Lookup corpus for records containing a watched domain and
emits one finding per source breach (their `message` groups matches by the
database the leak came from). A new source appearing = a new fingerprint = an
alert; a known one just refreshes.

Weekly cadence: the corpus changes slowly and the API is credit-metered.

PRIVACY — important. Leak-Lookup returns raw records, often `email:password`.
We never put those in the lake. Each record is parsed to a *masked* identifier
(local part shortened, secret dropped) and we keep only a count, a 3-item sample
and a has_passwords flag — enough to act on, not a re-hosted copy of the dump.
"""

from __future__ import annotations

import os
import time

from ..models import Company, Finding
from .base import BaseCollector

SEARCH = "https://leak-lookup.com/api/search"
# Leak-Lookup signals "nothing found" as an error string, not an empty result.
NO_RESULTS = "no results found"


def mask_identifier(identifier: str) -> str:
    """jo***@example.com — recognisable to an owner, not a fresh leak."""
    identifier = identifier.strip()
    if "@" in identifier:
        local, _, domain = identifier.partition("@")
        head = local[:2]
        return f"{head}{'*' * max(len(local) - 2, 1)}@{domain}"
    return identifier[:2] + "*" * max(len(identifier) - 2, 1)


def parse_record(record: str) -> tuple[str, bool]:
    """A leak record -> (masked identifier, whether a secret was attached).

    Records look like `user@example.com:password` or `user@example.com:hash` or
    sometimes just the email. We keep the masked identifier and a boolean; the
    secret itself is discarded immediately and never stored.
    """
    identifier, sep, secret = record.partition(":")
    return mask_identifier(identifier), bool(sep and secret.strip())


def summarize_source(records: list[str], sample_n: int = 3) -> tuple[int, list[str], bool]:
    """(count, masked sample, any-record-had-a-secret)."""
    masked, has_secret = [], False
    for rec in records:
        m, sec = parse_record(rec)
        masked.append(m)
        has_secret = has_secret or sec
    sample = sorted(set(masked))[:sample_n]
    return len(records), sample, has_secret


def severity_for(count: int, has_secret: bool) -> float:
    score = 45.0 + (15 if has_secret else 0) + min(count, 20)
    return min(score, 90.0)


class LeakLookupCollector(BaseCollector):
    NAME = "Leak-Lookup"
    KEY_ENV = "LEAKLOOKUP_API_KEY"
    CADENCE = "weekly"
    STATUS = "live"

    def __init__(self):
        super().__init__()
        self.delay = float(os.environ.get("LEAKLOOKUP_REQUEST_DELAY", "2"))

    def collect(self, companies: list[Company]) -> list[Finding]:
        http = self._http()
        findings: list[Finding] = []
        for co in companies:
            for domain in co.domains:
                if self.delay:
                    time.sleep(self.delay)
                try:
                    r = http.post(SEARCH, timeout=self.TIMEOUT, data={
                        "key": self.api_key, "type": "domain", "query": domain})
                    r.raise_for_status()
                    body = r.json()
                except Exception as e:  # noqa: BLE001
                    findings.append(self._err(co, domain, str(e)))
                    continue

                # error is a STRING ("true"/"false") in this API
                if str(body.get("error", "true")).lower() == "true":
                    msg = str(body.get("message", "")).strip()
                    if msg.lower() == NO_RESULTS:
                        continue  # clean — good news
                    findings.append(self._err(co, domain, msg or "unknown API error"))
                    continue

                sources = body.get("message", {})
                if not isinstance(sources, dict):
                    continue
                for source, records in sources.items():
                    if not isinstance(records, list):
                        continue
                    count, sample, has_secret = summarize_source(records)
                    findings.append(Finding(
                        company=co.name,
                        source=self.NAME,
                        kind="credential_leak",
                        title=f"{count} leaked record(s) for {domain} in {source}",
                        detail={
                            "_id": f"{domain}:{source}",
                            "domain": domain,
                            "leak_source": source,
                            "record_count": count,
                            "has_passwords": has_secret,
                            "sample": sample,           # masked, no secrets
                        },
                        evidence_url="https://leak-lookup.com/",
                        base_severity=severity_for(count, has_secret),
                    ))
        return findings

    def _err(self, co: Company, domain: str, msg: str) -> Finding:
        return Finding(
            company=co.name, source=self.NAME, kind="collector_error",
            title=f"Leak-Lookup search failed for {domain}",
            detail={"_id": f"err:{domain}", "error": msg}, base_severity=0)
