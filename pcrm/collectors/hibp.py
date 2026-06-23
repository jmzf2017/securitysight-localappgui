"""HaveIBeenPwned — breached accounts on a watched domain. Needs HIBP_API_KEY.

Uses the v3 `breacheddomain/{domain}` endpoint, which lists the email aliases on
a domain that appear in known breaches. It only works for domains you've verified
on your HIBP account — which is exactly the authorization model this project
wants: you monitor domains you control or are responsible for.

The endpoint returns {local_part: [BreachName, ...]}. We invert that to one
finding per (domain, breach): a new breach affecting the domain is a new
fingerprint, so it alerts; a breach we've already seen just refreshes last_seen.
Breach metadata (date, data classes, whether passwords were exposed) comes from
the public `/breaches` catalog in a single call, so we stay light on rate limits.

Privacy: we store the affected-account *count* plus a tiny sample of local-parts,
never the full list — enough to act on, not a fresh copy of the leak.

Rate limits are tier-based; set HIBP_REQUEST_DELAY (seconds) to match your plan.
429s are honoured via Retry-After.
"""

from __future__ import annotations

import os
import time

from ..models import Company, Finding
from .base import BaseCollector

API = "https://haveibeenpwned.com/api/v3"
# Data classes that mean leaked credentials are directly usable.
CREDENTIAL_CLASSES = {"Passwords", "Password hints", "Auth tokens",
                      "Security questions and answers"}


def invert_breached_domain(payload: dict[str, list[str]]) -> dict[str, list[str]]:
    """{local_part: [breach,...]} -> {breach: [local_part,...]}."""
    by_breach: dict[str, list[str]] = {}
    for local_part, breaches in (payload or {}).items():
        for b in breaches:
            by_breach.setdefault(b, []).append(local_part)
    return by_breach


def severity_for(meta: dict, affected: int) -> tuple[float, bool]:
    """Base severity for a breach finding + whether it exposed credentials."""
    classes = set(meta.get("DataClasses", []))
    has_creds = bool(classes & CREDENTIAL_CLASSES)
    score = 45.0
    if has_creds:
        score += 15
    score += min(affected, 20)              # scale a little with blast radius
    if (meta.get("BreachDate") or "") >= "2024-01-01":
        score += 10                          # a recent breach is more actionable
    return min(score, 95), has_creds


class HibpCollector(BaseCollector):
    NAME = "HaveIBeenPwned"
    KEY_ENV = "HIBP_API_KEY"
    CADENCE = "daily"
    STATUS = "live"

    def _http(self):
        s = super()._http()
        # HIBP rejects requests without a descriptive UA, and needs the key header.
        s.headers.update({"hibp-api-key": self.api_key or "",
                          "user-agent": "portco-risk-monitor"})
        return s

    def _get(self, url: str, **kw):
        """GET with one automatic retry honouring Retry-After on 429."""
        http = self._http()
        r = http.get(url, timeout=self.TIMEOUT, **kw)
        if r.status_code == 429:
            wait = int(r.headers.get("Retry-After", "5"))
            time.sleep(min(wait, 60))
            r = http.get(url, timeout=self.TIMEOUT, **kw)
        return r

    def _breach_catalog(self) -> dict[str, dict]:
        """name -> metadata, from the public catalog (single call)."""
        try:
            r = self._get(f"{API}/breaches")
            r.raise_for_status()
            return {b["Name"]: b for b in r.json()}
        except Exception:  # noqa: BLE001 - enrichment is best-effort
            return {}

    def collect(self, companies: list[Company]) -> list[Finding]:
        catalog = self._breach_catalog()
        delay = float(os.environ.get("HIBP_REQUEST_DELAY", "1.6"))
        findings: list[Finding] = []

        for co in companies:
            for domain in co.domains:
                try:
                    r = self._get(f"{API}/breacheddomain/{domain}")
                except Exception as e:  # noqa: BLE001
                    findings.append(self._err(co, domain, str(e)))
                    continue

                if r.status_code == 404:
                    continue  # no breached accounts on this domain — good news
                if r.status_code in (401, 403):
                    findings.append(self._err(
                        co, domain,
                        f"HTTP {r.status_code}: check HIBP_API_KEY and that "
                        f"'{domain}' is verified on your HIBP account"))
                    continue
                try:
                    r.raise_for_status()
                    by_breach = invert_breached_domain(r.json())
                except Exception as e:  # noqa: BLE001
                    findings.append(self._err(co, domain, str(e)))
                    continue

                for breach, accounts in by_breach.items():
                    meta = catalog.get(breach, {})
                    sev, has_creds = severity_for(meta, len(accounts))
                    title = (f"{len(accounts)} account(s) at {domain} in "
                             f"{meta.get('Title', breach)} breach")
                    findings.append(Finding(
                        company=co.name,
                        source=self.NAME,
                        kind="breached_accounts",
                        title=title,
                        detail={
                            "_id": f"{domain}:{breach}",
                            "domain": domain,
                            "breach": breach,
                            "breach_title": meta.get("Title", breach),
                            "breach_date": meta.get("BreachDate"),
                            "data_classes": meta.get("DataClasses", []),
                            "has_passwords": has_creds,
                            "affected_accounts": len(accounts),
                            "sample": sorted(accounts)[:3],  # tiny sample only
                        },
                        evidence_url=f"https://haveibeenpwned.com/breach/{breach}",
                        base_severity=sev,
                    ))
                if delay:
                    time.sleep(delay)
        return findings

    def _err(self, co: Company, domain: str, msg: str) -> Finding:
        return Finding(
            company=co.name, source=self.NAME, kind="collector_error",
            title=f"HIBP lookup failed for {domain}",
            detail={"_id": f"err:{domain}", "error": msg}, base_severity=0)
