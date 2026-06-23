"""VirusTotal — domain reputation & passive DNS. Needs VT_API_KEY.

Two signals per watched domain, both economical on API credits:

  malicious_verdict : AV/URL engines flagging the company's own domain. A domain
                      you own being flagged usually means it's serving malware,
                      is defaced, or has a compromised host — high signal.
  passive_dns       : recent IPs the domain resolved to (VT's passive DNS). A new
                      resolution can mean new infra or a takeover; if the IP it
                      now points at is itself flagged malicious, that escalates.

VT's free tier is ~4 requests/min. We pace every call by VT_REQUEST_DELAY seconds
(default 15, free-tier safe) and honour Retry-After on 429. Passive DNS is one
extra call per domain; disable it with VT_PASSIVE_DNS=0 to halve credit use.
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone, timedelta

from ..models import Company, Finding
from .base import BaseCollector

API = "https://www.virustotal.com/api/v3"


def verdict_severity(malicious: int, suspicious: int, reputation: int) -> tuple[bool, float, str]:
    """Decide whether a domain report is worth a finding, and how bad.

    Returns (emit, severity, label). A clean, well-reputed domain emits nothing.
    """
    if malicious == 0 and suspicious < 2 and reputation > -10:
        return False, 0.0, "clean"
    if malicious > 0:
        score = 55 + min(malicious * 7, 35)
        label = "malicious"
    elif suspicious >= 2:
        score = 40 + min(suspicious * 4, 20)
        label = "suspicious"
    else:
        score = 35
        label = "poor-reputation"
    if reputation < -20:
        score += 5
    return True, min(score, 95), label


def top_flagging_engines(results: dict, limit: int = 5) -> list[str]:
    """Names of the engines that called a domain malicious/suspicious."""
    flagged = [name for name, r in (results or {}).items()
               if r.get("category") in ("malicious", "suspicious")]
    return sorted(flagged)[:limit]


class VirusTotalCollector(BaseCollector):
    NAME = "VirusTotal"
    KEY_ENV = "VT_API_KEY"
    CADENCE = "daily"
    STATUS = "live"

    def __init__(self):
        super().__init__()
        self.delay = float(os.environ.get("VT_REQUEST_DELAY", "15"))
        self.passive_dns = os.environ.get("VT_PASSIVE_DNS", "1") != "0"
        self.lookback_days = int(os.environ.get("VT_DNS_LOOKBACK_DAYS", "30"))

    def _http(self):
        s = super()._http()
        s.headers.update({"x-apikey": self.api_key or ""})
        return s

    def _get(self, path: str, **params):
        """Paced GET with one Retry-After-aware retry on 429."""
        time.sleep(self.delay)
        http = self._http()
        r = http.get(f"{API}{path}", params=params or None, timeout=self.TIMEOUT)
        if r.status_code == 429:
            wait = int(r.headers.get("Retry-After", str(int(self.delay) or 15)))
            time.sleep(min(wait, 90))
            r = http.get(f"{API}{path}", params=params or None, timeout=self.TIMEOUT)
        return r

    def collect(self, companies: list[Company]) -> list[Finding]:
        findings: list[Finding] = []
        for co in companies:
            for domain in co.domains:
                findings.extend(self._domain_verdict(co, domain))
                if self.passive_dns:
                    findings.extend(self._passive_dns(co, domain))
        return findings

    # ------------------------------------------------------------ verdict
    def _domain_verdict(self, co: Company, domain: str) -> list[Finding]:
        try:
            r = self._get(f"/domains/{domain}")
            if r.status_code == 404:
                return []  # VT has never seen it
            r.raise_for_status()
            attrs = r.json().get("data", {}).get("attributes", {})
        except Exception as e:  # noqa: BLE001
            return [self._err(co, domain, str(e))]

        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        reputation = int(attrs.get("reputation", 0))
        emit, sev, label = verdict_severity(malicious, suspicious, reputation)
        if not emit:
            return []

        engines = top_flagging_engines(attrs.get("last_analysis_results", {}))
        return [Finding(
            company=co.name,
            source=self.NAME,
            kind="malicious_verdict",
            title=f"{malicious or suspicious} engine(s) flag {domain} as {label}",
            detail={
                "_id": f"{domain}:reputation",
                "domain": domain,
                "malicious": malicious, "suspicious": suspicious,
                "harmless": int(stats.get("harmless", 0)),
                "reputation": reputation,
                "flagging_engines": engines,
                "categories": list((attrs.get("categories") or {}).values())[:5],
            },
            evidence_url=f"https://www.virustotal.com/gui/domain/{domain}",
            base_severity=sev,
        )]

    # -------------------------------------------------------- passive DNS
    def _passive_dns(self, co: Company, domain: str) -> list[Finding]:
        try:
            r = self._get(f"/domains/{domain}/resolutions", limit=20)
            if r.status_code == 404:
                return []
            r.raise_for_status()
            rows = r.json().get("data", [])
        except Exception as e:  # noqa: BLE001
            return [self._err(co, domain, str(e))]

        cutoff = datetime.now(timezone.utc) - timedelta(days=self.lookback_days)
        findings: list[Finding] = []
        for row in rows:
            a = row.get("attributes", {})
            ip = a.get("ip_address")
            ts = a.get("date")
            if not ip or not ts:
                continue
            when = datetime.fromtimestamp(int(ts), tz=timezone.utc)
            if when < cutoff:
                continue  # only recently-changed resolutions are interesting
            ip_mal = int((a.get("ip_address_last_analysis_stats") or {}).get("malicious", 0))
            if ip_mal > 0:
                sev = 60 + min(ip_mal * 6, 30)
                title = f"{domain} resolves to flagged IP {ip} ({ip_mal} engines)"
            else:
                sev = 15  # informational drift signal
                title = f"{domain} resolved to new IP {ip}"
            findings.append(Finding(
                company=co.name,
                source=self.NAME,
                kind="passive_dns",
                title=title,
                detail={
                    "_id": f"{domain}->{ip}",
                    "domain": domain, "ip": ip,
                    "resolved_at": when.date().isoformat(),
                    "ip_malicious_engines": ip_mal,
                },
                evidence_url=f"https://www.virustotal.com/gui/ip-address/{ip}",
                base_severity=sev,
            ))
        return findings

    def _err(self, co: Company, domain: str, msg: str) -> Finding:
        return Finding(
            company=co.name, source=self.NAME, kind="collector_error",
            title=f"VirusTotal lookup failed for {domain}",
            detail={"_id": f"err:{domain}", "error": msg}, base_severity=0)
