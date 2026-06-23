"""crt.sh — Certificate Transparency logs. No API key.

New certificates for a domain reveal new subdomains/hosts as they come online.
A subdomain you didn't know existed is the start of most attack-surface drift,
so each newly observed SAN becomes a low/info finding that the scorer can
escalate if another source later flags the same host.
"""

from __future__ import annotations

from ..models import Company, Finding
from .base import BaseCollector


class CrtShCollector(BaseCollector):
    NAME = "crt.sh"
    KEY_ENV = ""
    CADENCE = "daily"
    STATUS = "live"

    URL = "https://crt.sh/"

    def collect(self, companies: list[Company]) -> list[Finding]:
        findings: list[Finding] = []
        http = self._http()
        for co in companies:
            for domain in co.domains:
                try:
                    r = http.get(
                        self.URL,
                        params={"q": f"%.{domain}", "output": "json"},
                        timeout=self.TIMEOUT,
                    )
                    r.raise_for_status()
                    rows = r.json()
                except Exception as e:  # noqa: BLE001 - degrade, never crash a run
                    findings.append(self._error(co, domain, e))
                    continue

                # crt.sh returns one row per (cert, name_value); name_value may be
                # newline-delimited SANs. Collapse to the set of distinct hostnames.
                hosts: set[str] = set()
                for row in rows:
                    for name in (row.get("name_value") or "").split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(domain):
                            hosts.add(name)

                for host in sorted(hosts):
                    findings.append(
                        Finding(
                            company=co.name,
                            source=self.NAME,
                            kind="certificate_host",
                            title=f"Host in CT logs: {host}",
                            detail={"_id": host, "host": host, "root": domain},
                            evidence_url=f"https://crt.sh/?q={host}",
                            base_severity=10,  # info; scorer escalates on overlap
                        )
                    )
        return findings

    def _error(self, co: Company, domain: str, e: Exception) -> Finding:
        return Finding(
            company=co.name,
            source=self.NAME,
            kind="collector_error",
            title=f"crt.sh lookup failed for {domain}",
            detail={"_id": f"err:{domain}", "error": str(e)},
            base_severity=0,
        )
