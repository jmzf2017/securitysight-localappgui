"""Shodan — passive view of internet-exposed services. Needs SHODAN_API_KEY.

Queries Shodan's *index* (it does not scan the targets itself) for hosts matching
each watched domain, and turns each exposed service into a finding. Risky service
classes (remote access, databases, admin panels) get a higher base severity, and
any Shodan-reported `vulns` ride along in detail for the scorer to correlate
against KEV.
"""

from __future__ import annotations

from ..models import Company, Finding
from .base import BaseCollector

SEARCH = "https://api.shodan.io/shodan/host/search"

# Ports that shouldn't be facing the internet for most orgs.
RISKY_PORTS = {
    3389: "RDP", 23: "Telnet", 445: "SMB", 5900: "VNC", 1433: "MSSQL",
    3306: "MySQL", 5432: "Postgres", 27017: "MongoDB", 6379: "Redis",
    9200: "Elasticsearch", 11211: "Memcached", 2375: "Docker API",
}


class ShodanCollector(BaseCollector):
    NAME = "Shodan"
    KEY_ENV = "SHODAN_API_KEY"
    CADENCE = "daily"
    STATUS = "live"

    def _validate_live(self, key: str) -> dict | None:
        """Cheap key check: Shodan's /api-info echoes plan/credits for a valid key."""
        try:
            r = self._http().get("https://api.shodan.io/api-info",
                                 params={"key": key}, timeout=self.TIMEOUT)
            if r.status_code == 200:
                return {"ok": True, "detail": "verified via Shodan api-info"}
            return {"ok": False, "detail": f"Shodan rejected the key (HTTP {r.status_code})"}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "detail": f"Shodan check failed: {e}"}

    def collect(self, companies: list[Company]) -> list[Finding]:
        http = self._http()
        findings: list[Finding] = []
        for co in companies:
            for domain in co.domains:
                try:
                    r = http.get(
                        SEARCH,
                        params={"key": self.api_key, "query": f"hostname:{domain}"},
                        timeout=self.TIMEOUT,
                    )
                    r.raise_for_status()
                    matches = r.json().get("matches", [])
                except Exception as e:  # noqa: BLE001
                    findings.append(Finding(
                        company=co.name, source=self.NAME, kind="collector_error",
                        title=f"Shodan query failed for {domain}",
                        detail={"_id": f"err:{domain}", "error": str(e)},
                        base_severity=0))
                    continue

                for m in matches:
                    ip, port = m.get("ip_str"), m.get("port")
                    product = m.get("product") or ""
                    version = m.get("version") or ""
                    vulns = list((m.get("vulns") or {}).keys())
                    risky = RISKY_PORTS.get(port)
                    sev = 60 if risky else 30
                    if vulns:
                        sev = max(sev, 70)
                    title = f"{ip}:{port}"
                    if risky:
                        title += f" ({risky} exposed)"
                    elif product:
                        title += f" ({product} {version})".rstrip()

                    findings.append(Finding(
                        company=co.name,
                        source=self.NAME,
                        kind="exposed_service",
                        title=title,
                        detail={
                            "_id": f"{ip}:{port}",
                            "ip": ip, "port": port, "transport": m.get("transport"),
                            "product": product, "version": version,
                            "risky_service": risky,
                            "vulns": vulns,         # consumed by KEV correlation
                            "hostnames": m.get("hostnames", []),
                            "org": m.get("org"),
                        },
                        evidence_url=f"https://www.shodan.io/host/{ip}",
                        base_severity=sev,
                    ))
        return findings
