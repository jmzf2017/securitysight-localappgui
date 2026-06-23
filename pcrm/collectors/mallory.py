"""Mallory.ai — breach + vulnerability intel. Both need MALLORY_API_KEY.

Two collectors share the key because they're two lenses on the same provider:

  Mallory-Breaches : has this company shown up in a known breach / dump?
  Mallory-Vulns    : vulnerability intel (often with exploit-maturity signal,
                      which is more actionable than a raw CVSS score).

The exact request/response shape depends on Mallory's API. The query construction
and field mapping live in one place per collector so adapting to the live schema
is a small edit. Both fail soft.
"""

from __future__ import annotations

from ..models import Company, Finding
from .base import BaseCollector

BASE = "https://api.mallory.ai/v1"


class _MalloryBase(BaseCollector):
    KEY_ENV = "MALLORY_API_KEY"
    CADENCE = "daily"
    STATUS = "live"

    def _http(self):
        s = super()._http()
        s.headers.update({"Authorization": f"Bearer {self.api_key}"})
        return s


class MalloryBreachesCollector(_MalloryBase):
    NAME = "Mallory-Breaches"

    def collect(self, companies: list[Company]) -> list[Finding]:
        http = self._http()
        findings: list[Finding] = []
        for co in companies:
            for domain in co.domains:
                try:
                    r = http.get(f"{BASE}/breaches",
                                 params={"domain": domain}, timeout=self.TIMEOUT)
                    r.raise_for_status()
                    breaches = r.json().get("data", [])
                except Exception as e:  # noqa: BLE001
                    findings.append(Finding(
                        company=co.name, source=self.NAME, kind="collector_error",
                        title=f"Mallory breaches query failed for {domain}",
                        detail={"_id": f"err:{domain}", "error": str(e)},
                        base_severity=0))
                    continue
                for b in breaches:
                    findings.append(Finding(
                        company=co.name,
                        source=self.NAME,
                        kind="breach",
                        title=f"Breach exposure: {b.get('name', 'unnamed')}",
                        detail={
                            "_id": f"{domain}:{b.get('id', b.get('name'))}",
                            "name": b.get("name"),
                            "breach_date": b.get("breach_date"),
                            "records": b.get("record_count"),
                            "classes": b.get("data_classes", []),
                            "domain": domain,
                        },
                        base_severity=55,
                    ))
        return findings


class MalloryVulnsCollector(_MalloryBase):
    NAME = "Mallory-Vulns"

    def collect(self, companies: list[Company]) -> list[Finding]:
        http = self._http()
        findings: list[Finding] = []
        for co in companies:
            tags = [t for t in co.tags]
            for product in tags:  # tags double as the product/tech inventory
                try:
                    r = http.get(f"{BASE}/vulnerabilities",
                                 params={"product": product}, timeout=self.TIMEOUT)
                    r.raise_for_status()
                    vulns = r.json().get("data", [])
                except Exception as e:  # noqa: BLE001
                    findings.append(Finding(
                        company=co.name, source=self.NAME, kind="collector_error",
                        title=f"Mallory vulns query failed for {product}",
                        detail={"_id": f"err:{product}", "error": str(e)},
                        base_severity=0))
                    continue
                for v in vulns:
                    exploited = v.get("exploited") or v.get("in_the_wild")
                    findings.append(Finding(
                        company=co.name,
                        source=self.NAME,
                        kind="vuln_intel",
                        title=f"{v.get('cve')} in {product}",
                        detail={
                            "_id": f"{co.name}:{v.get('cve')}",
                            "cve": v.get("cve"),
                            "product": product,
                            "cvss": v.get("cvss"),
                            "exploit_maturity": v.get("exploit_maturity"),
                            "exploited": exploited,
                        },
                        evidence_url=f"https://nvd.nist.gov/vuln/detail/{v.get('cve')}",
                        base_severity=45 if exploited else 25,
                    ))
        return findings
