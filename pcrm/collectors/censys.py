"""Censys — second opinion on exposed hosts. Needs CENSYS_PAT.

Uses the Censys Platform search API (bearer personal access token). Censys and
Shodan see overlapping but not identical surface, so corroboration across both
raises confidence; the scorer treats a host seen by both as higher signal.

NOTE: Censys has revised its API surface over time. This targets the Platform
search endpoint with a PAT. If your tenant uses a different host/path or the
legacy API ID + secret, adjust SEARCH and the auth header here only.
"""

from __future__ import annotations

from ..models import Company, Finding
from .base import BaseCollector
from .shodan import RISKY_PORTS

SEARCH = "https://api.platform.censys.io/v3/global/search/query"


class CensysCollector(BaseCollector):
    NAME = "Censys"
    KEY_ENV = "CENSYS_PAT"
    CADENCE = "daily"
    STATUS = "live"

    def collect(self, companies: list[Company]) -> list[Finding]:
        http = self._http()
        http.headers.update({"Authorization": f"Bearer {self.api_key}"})
        findings: list[Finding] = []
        for co in companies:
            for domain in co.domains:
                try:
                    r = http.post(
                        SEARCH,
                        json={"query": f"dns.names: {domain}", "page_size": 50},
                        timeout=self.TIMEOUT,
                    )
                    r.raise_for_status()
                    hits = r.json().get("result", {}).get("hits", [])
                except Exception as e:  # noqa: BLE001
                    findings.append(Finding(
                        company=co.name, source=self.NAME, kind="collector_error",
                        title=f"Censys query failed for {domain}",
                        detail={"_id": f"err:{domain}", "error": str(e)},
                        base_severity=0))
                    continue

                for h in hits:
                    ip = h.get("ip")
                    for svc in h.get("services", []):
                        port = svc.get("port")
                        risky = RISKY_PORTS.get(port)
                        sev = 60 if risky else 30
                        title = f"{ip}:{port}"
                        if risky:
                            title += f" ({risky} exposed)"
                        findings.append(Finding(
                            company=co.name,
                            source=self.NAME,
                            kind="exposed_service",
                            title=title,
                            detail={
                                "_id": f"{ip}:{port}",
                                "ip": ip, "port": port,
                                "service": svc.get("service_name"),
                                "risky_service": risky,
                            },
                            evidence_url=f"https://platform.censys.io/hosts/{ip}",
                            base_severity=sev,
                        ))
        return findings
