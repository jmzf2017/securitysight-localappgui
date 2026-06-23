#!/usr/bin/env python3
"""Seed the lake with realistic sample findings so you can see the dashboard,
scoring and correlations without wiring up API keys first.

Run:  uv run seed_demo.py     then:  uv run dashboard.py

It writes a small fake CISA KEV cache (so the KEV<->exposed-service correlation
fires) and a spread of findings designed to trigger every escalation path.
Delete data/ to reset.
"""

from __future__ import annotations

import json
from pathlib import Path

from pcrm.config import ensure_config_seeded
from pcrm.lake import Lake
from pcrm.store import Store, db_path
from pcrm.models import Finding
from pcrm.scoring import score_all
from pcrm.assets import enrich_assets
from pcrm.collectors import cisa_kev

# --- fake KEV catalog covering the CVEs used below -------------------------
KEV = {
    "vulnerabilities": [
        {"cveID": "CVE-2023-34362", "vendorProject": "Progress",
         "product": "MOVEit Transfer", "knownRansomwareCampaignUse": "Known",
         "vulnerabilityName": "MOVEit SQLi", "dueDate": "2023-06-23"},
        {"cveID": "CVE-2024-21887", "vendorProject": "Ivanti",
         "product": "Connect Secure", "knownRansomwareCampaignUse": "Known",
         "vulnerabilityName": "Ivanti command injection", "dueDate": "2024-01-22"},
        {"cveID": "CVE-2023-27997", "vendorProject": "Fortinet",
         "product": "FortiOS", "knownRansomwareCampaignUse": "Unknown",
         "vulnerabilityName": "FortiOS heap overflow", "dueDate": "2023-07-11"},
    ]
}


def F(**kw) -> Finding:
    return Finding(**kw)

SEED = [
    # Meridian Health: on a ransomware leak site (critical on its own) ...
    F(company="Meridian Health", source="RansomLook", kind="ransomware_mention",
      title="Listed on LockBit leak site",
      detail={"_id": "Meridian:LockBit", "group": "LockBit",
              "post_title": "Meridian Health Systems"},
      evidence_url="https://www.ransomlook.io/", base_severity=95),
    # ... and has an exposed RDP running a KEV CVE -> everything escalates
    F(company="Meridian Health", source="Shodan", kind="exposed_service",
      title="203.0.113.10:3389 (RDP exposed)",
      detail={"_id": "203.0.113.10:3389", "ip": "203.0.113.10", "port": 3389,
              "risky_service": "RDP", "vulns": ["CVE-2024-21887"],
              "hostnames": ["vpn.meridianhealth.example"]},
      evidence_url="https://www.shodan.io/host/203.0.113.10", base_severity=60),

    # Northwind: Fortinet KEV match on an exposed box, seen by both scanners
    F(company="Northwind Logistics", source="Shodan", kind="exposed_service",
      title="198.51.100.5:443 (FortiOS 7.0)",
      detail={"_id": "198.51.100.5:443", "ip": "198.51.100.5", "port": 443,
              "product": "FortiOS", "version": "7.0", "vulns": ["CVE-2023-27997"],
              "hostnames": ["fw.northwind-logistics.example"]},
      evidence_url="https://www.shodan.io/host/198.51.100.5", base_severity=70),
    F(company="Northwind Logistics", source="Censys", kind="exposed_service",
      title="198.51.100.5:443 (FortiOS)",
      detail={"_id": "198.51.100.5:443", "ip": "198.51.100.5", "port": 443,
              "service": "HTTPS", "risky_service": None},
      evidence_url="https://platform.censys.io/hosts/198.51.100.5", base_severity=30),

    # Cedar Mfg: MOVEit (ransomware-linked KEV) via vuln intel + tag match
    F(company="Cedar Manufacturing", source="NVD-KEV", kind="kev_product_match",
      title="KEV affects Progress MOVEit Transfer: CVE-2023-34362",
      detail={"_id": "Cedar Manufacturing:CVE-2023-34362", "cve": "CVE-2023-34362",
              "vendor": "Progress", "product": "MOVEit Transfer",
              "ransomware_use": "Known"},
      evidence_url="https://nvd.nist.gov/vuln/detail/CVE-2023-34362",
      base_severity=92),

    # Leak-Lookup: credentials for Cedar in a corpus source. Cedar has no exposed
    # remote-access service, so this stays a standalone high (no correlation boost)
    # and the sample is masked — the lake never stores the raw email:password lines.
    F(company="Cedar Manufacturing", source="Leak-Lookup", kind="credential_leak",
      title="8 leaked record(s) for cedarmfg.example in Collection #2",
      detail={"_id": "cedarmfg.example:Collection #2", "domain": "cedarmfg.example",
              "leak_source": "Collection #2", "record_count": 8,
              "has_passwords": True,
              "sample": ["ad***@cedarmfg.example", "jo***@cedarmfg.example",
                         "pl***@cedarmfg.example"]},
      evidence_url="https://leak-lookup.com/", base_severity=68),

    # Atlas Fintech: exposed Postgres + a breach -> breach+remote-access boost
    F(company="Atlas Fintech", source="Shodan", kind="exposed_service",
      title="192.0.2.20:5432 (Postgres exposed)",
      detail={"_id": "192.0.2.20:5432", "ip": "192.0.2.20", "port": 5432,
              "risky_service": "Postgres", "vulns": [],
              "hostnames": ["db.atlasfintech.example"]},
      evidence_url="https://www.shodan.io/host/192.0.2.20", base_severity=60),
    F(company="Atlas Fintech", source="Mallory-Breaches", kind="breach",
      title="Breach exposure: PayDump 2025",
      detail={"_id": "atlasfintech.example:paydump25", "name": "PayDump 2025",
              "records": 48000, "classes": ["emails", "passwords"]},
      base_severity=55),

    # HIBP: leaked employee creds at Meridian, which also has exposed RDP ->
    # the scorer ties the two together (credentials + remote access = a way in)
    F(company="Meridian Health", source="HaveIBeenPwned", kind="breached_accounts",
      title="14 account(s) at meridianhealth.example in Collection #1 breach",
      detail={"_id": "meridianhealth.example:Collection1",
              "domain": "meridianhealth.example", "breach": "Collection1",
              "breach_title": "Collection #1", "breach_date": "2019-01-07",
              "data_classes": ["Email addresses", "Passwords"],
              "has_passwords": True, "affected_accounts": 14,
              "sample": ["a.smith", "billing", "j.doe"]},
      evidence_url="https://haveibeenpwned.com/breach/Collection1",
      base_severity=60),

    # VirusTotal: Atlas's own domain flagged malicious; Atlas also has exposed
    # Postgres -> scorer reads that as a likely compromised host, not a stray hit
    F(company="Atlas Fintech", source="VirusTotal", kind="malicious_verdict",
      title="6 engine(s) flag atlasfintech.example as malicious",
      detail={"_id": "atlasfintech.example:reputation", "domain": "atlasfintech.example",
              "malicious": 6, "suspicious": 2, "harmless": 70, "reputation": -34,
              "flagging_engines": ["BitDefender", "Fortinet", "Google Safebrowsing",
                                   "Kaspersky", "Sophos"],
              "categories": ["malware"]},
      evidence_url="https://www.virustotal.com/gui/domain/atlasfintech.example",
      base_severity=89),
    # ... and a benign passive-DNS drift signal that stays informational
    F(company="Northwind Logistics", source="VirusTotal", kind="passive_dns",
      title="northwind-logistics.example resolved to new IP 198.51.100.77",
      detail={"_id": "northwind-logistics.example->198.51.100.77",
              "domain": "northwind-logistics.example", "ip": "198.51.100.77",
              "resolved_at": "2026-06-21", "ip_malicious_engines": 0},
      evidence_url="https://www.virustotal.com/gui/ip-address/198.51.100.77",
      base_severity=15),

    # Northwind: an Exchange KEV (matched on the 'exchange' tag) PLUS an exposed
    # Exchange host and an autodiscover cert host -> the enrichment ties them
    # together so the KEV finding shows *where* to look.
    F(company="Northwind Logistics", source="NVD-KEV", kind="kev_product_match",
      title="KEV affects Microsoft Exchange Server: CVE-2021-31207",
      detail={"_id": "Northwind Logistics:CVE-2021-31207", "cve": "CVE-2021-31207",
              "vendor": "Microsoft", "product": "Exchange Server",
              "matched_tags": ["exchange"], "ransomware_use": "Known",
              "name": "Microsoft Exchange Server Security Feature Bypass"},
      evidence_url="https://nvd.nist.gov/vuln/detail/CVE-2021-31207",
      base_severity=92),
    F(company="Northwind Logistics", source="Shodan", kind="exposed_service",
      title="198.51.100.9:443 (Microsoft Exchange)",
      detail={"_id": "198.51.100.9:443", "ip": "198.51.100.9", "port": 443,
              "product": "Microsoft Exchange", "version": "2016",
              "hostnames": ["mail.northwind-logistics.example"], "vulns": []},
      evidence_url="https://www.shodan.io/host/198.51.100.9", base_severity=40),
    F(company="Northwind Logistics", source="crt.sh", kind="certificate_host",
      title="Host in CT logs: autodiscover.northwind-logistics.example",
      detail={"_id": "autodiscover.northwind-logistics.example",
              "host": "autodiscover.northwind-logistics.example",
              "root": "northwind-logistics.example"},
      evidence_url="https://crt.sh/?q=autodiscover.northwind-logistics.example",
      base_severity=10),

    # crt.sh: a new cert host that matches an exposed host -> escalates from info
    F(company="Meridian Health", source="crt.sh", kind="certificate_host",
      title="Host in CT logs: vpn.meridianhealth.example",
      detail={"_id": "vpn.meridianhealth.example",
              "host": "vpn.meridianhealth.example", "root": "meridianhealth.example"},
      evidence_url="https://crt.sh/?q=vpn.meridianhealth.example", base_severity=10),
    # ... and one that stays low (no overlap)
    F(company="Atlas Fintech", source="crt.sh", kind="certificate_host",
      title="Host in CT logs: marketing.atlasfintech.example",
      detail={"_id": "marketing.atlasfintech.example",
              "host": "marketing.atlasfintech.example", "root": "atlasfintech.example"},
      base_severity=10),
]


def seed(data_root: str = "data") -> dict:
    """Seed the lake at ``data_root`` with demo findings (+ a fake KEV cache so
    correlations fire) and the demo watchlist. Returns {"new", "total"}."""
    store = Store(db_path(data_root))
    ensure_config_seeded(store)                  # demo watchlist if store is empty
    cisa_kev.CACHE.parent.mkdir(parents=True, exist_ok=True)
    cisa_kev.CACHE.write_text(json.dumps(KEV))
    lake = Lake(store)
    result = lake.ingest(SEED)
    enrich_assets(lake.all_findings())           # locate hosts first
    scored = score_all(lake.all_findings(), {c.name: c for c in store.get_companies()})
    lake.rescore(scored)
    return {"new": len(result["new"]), "total": len(lake.all_findings())}


def main() -> None:
    res = seed()
    lake = Lake("data")
    print(f"seeded {res['new']} new findings\n")
    top = sorted(lake.all_findings(), key=lambda f: f["score"], reverse=True)
    for f in top:
        print(f"  {f['score']:>5} {f['severity']:<8} {f['company']:<22} "
              f"{f['source']:<16} {f['title']}")
        for r in f.get("score_reasons", []):
            print(f"        ↳ {r}")


if __name__ == "__main__":
    main()
