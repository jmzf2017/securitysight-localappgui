"""CISA KEV — Known Exploited Vulnerabilities catalog. No API key.

KEV is the "these are being exploited in the wild right now" list. It's keyed by
vendor/product, not by company, so it does two jobs:

  1. Emits a finding for any company whose tags name a vendor/product currently
     in KEV (e.g. a company tagged `fortinet` when a Fortinet CVE is KEV-listed).
  2. Caches the whole catalog to data/cache/cisa_kev.json so the scoring engine
     can correlate it against exposed services found by Shodan/Censys — an
     exposed service running a KEV-listed product is the real "worry today".
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..models import Company, Finding
from .base import BaseCollector

FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# Cache lives under the data root (honors PCRM_DATA so the desktop app keeps it
# in the per-user data dir alongside the lake).
CACHE = Path(os.environ.get("PCRM_DATA", "data")) / "cache" / "cisa_kev.json"


def load_cached_catalog() -> list[dict]:
    """Used by the scoring engine. Returns [] if no run has fetched it yet."""
    if CACHE.exists():
        return json.loads(CACHE.read_text()).get("vulnerabilities", [])
    return []


class CisaKevCollector(BaseCollector):
    NAME = "NVD-KEV"
    KEY_ENV = ""
    CADENCE = "daily"
    STATUS = "live"  # free public feed, so no reason to leave it a stub

    def collect(self, companies: list[Company]) -> list[Finding]:
        http = self._http()
        try:
            r = http.get(FEED, timeout=self.TIMEOUT)
            r.raise_for_status()
            catalog = r.json()
        except Exception as e:  # noqa: BLE001
            return [Finding(
                company="(catalog)", source=self.NAME, kind="collector_error",
                title="CISA KEV feed fetch failed",
                detail={"_id": "kev:err", "error": str(e)}, base_severity=0,
            )]

        CACHE.parent.mkdir(parents=True, exist_ok=True)
        CACHE.write_text(json.dumps(catalog))
        vulns = catalog.get("vulnerabilities", [])

        # Build a lowercase vendor/product index for tag matching.
        findings: list[Finding] = []
        for co in companies:
            tags = {t.lower() for t in co.tags}
            if not tags:
                continue
            for v in vulns:
                hay = f"{v.get('vendorProject','')} {v.get('product','')}".lower()
                matched = [t for t in co.tags if t.lower() in hay]
                if matched:
                    ransom = v.get("knownRansomwareCampaignUse", "Unknown")
                    findings.append(Finding(
                        company=co.name,
                        source=self.NAME,
                        kind="kev_product_match",
                        title=f"KEV affects {v.get('vendorProject')} "
                              f"{v.get('product')}: {v.get('cveID')}",
                        detail={
                            "_id": f"{co.name}:{v.get('cveID')}",
                            "cve": v.get("cveID"),
                            "vendor": v.get("vendorProject"),
                            "product": v.get("product"),
                            "matched_tags": matched,
                            "due_date": v.get("dueDate"),
                            "ransomware_use": ransom,
                            "name": v.get("vulnerabilityName"),
                        },
                        evidence_url=f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}",
                        # uncorroborated tag match by default; scoring promotes
                        # this if asset enrichment finds a real host running it
                        base_severity=40 if ransom == "Known" else 25,
                    ))
        return findings
