"""Scoring & correlation — the part that decides what to worry about.

Runs over the *entire* lake each pass (not just today's new findings) because
the interesting signal is cross-source: a single exposed Postgres is a shrug; an
exposed Postgres running a CVE that's on CISA KEV, at a company that also just
appeared on a ransomware leak site, is a fire.

Every score change records a human-readable reason. The dashboard shows those
reasons, so an analyst sees *why* something is ranked where it is — that's the
difference between a feed and a number.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

from .models import severity_label
from .collectors.cisa_kev import load_cached_catalog


def _recent(iso_ts: str | None, days: int) -> bool:
    if not iso_ts:
        return False
    try:
        t = datetime.fromisoformat(iso_ts)
    except ValueError:
        return False
    return datetime.now(timezone.utc) - t <= timedelta(days=days)


def score_all(findings: list[dict], companies: dict[str, "Company"]) -> list[dict]:
    """Annotate each finding with `score`, `severity`, `score_reasons`.

    `findings` are lake records (dicts). `companies` maps name -> Company.
    """
    # --- index KEV CVEs once for fast membership tests -----------------------
    kev = load_cached_catalog()
    kev_cves = {v.get("cveID") for v in kev}
    kev_ransom = {v.get("cveID") for v in kev
                  if v.get("knownRansomwareCampaignUse") == "Known"}

    # --- group by company for cross-source correlation -----------------------
    by_company: dict[str, list[dict]] = {}
    for f in findings:
        by_company.setdefault(f["company"], []).append(f)

    for company, items in by_company.items():
        kinds = {i["kind"] for i in items}
        company_has_ransom = "ransomware_mention" in kinds
        # IP/host seen across multiple scanners → corroboration
        seen_by: dict[str, set[str]] = {}
        for i in items:
            host_id = i.get("detail", {}).get("_id")
            if i["kind"] == "exposed_service" and host_id:
                seen_by.setdefault(host_id, set()).add(i["source"])
        # set of hosts that some scanner confirmed exposed (to escalate cert hosts)
        exposed_hosts = {
            h.lower()
            for i in items if i["kind"] == "exposed_service"
            for h in i.get("detail", {}).get("hostnames", [])
        }

        for f in items:
            score = float(f.get("base_severity", 0))
            reasons: list[str] = []
            detail = f.get("detail", {})

            # 1) exposed service running a KEV-listed CVE -> top priority
            if f["kind"] == "exposed_service":
                hit = [c for c in detail.get("vulns", []) if c in kev_cves]
                ransom_hit = [c for c in hit if c in kev_ransom]
                if ransom_hit:
                    score = max(score, 97)
                    reasons.append(f"exposed service runs ransomware-linked KEV CVE "
                                   f"({', '.join(ransom_hit)})")
                elif hit:
                    score = max(score, 90)
                    reasons.append(f"exposed service runs actively-exploited KEV CVE "
                                   f"({', '.join(hit)})")
                # corroborated by 2+ scanners
                hid = detail.get("_id")
                if hid and len(seen_by.get(hid, set())) > 1:
                    score += 6
                    reasons.append("confirmed by multiple scanners")

            # 1b) product/inventory match (KEV or vuln intel matched on a tech
            #     TAG, not a host). Score by EVIDENCE, not by the bare tag:
            #     a tag is your assertion that you run something, not proof a
            #     vulnerable instance exists or is reachable.
            if f["kind"] in ("kev_product_match", "vuln_intel"):
                assets = detail.get("affected_assets", []) or []
                exposed = any(a.get("exposed") for a in assets)
                ransom = (detail.get("ransomware_use") == "Known"
                          or bool(detail.get("exploited")))
                if exposed:
                    score = 97 if ransom else 90
                    reasons.append("affected product runs on an internet-exposed host")
                elif assets:
                    score = 65 if ransom else 50
                    reasons.append("affected product matches a candidate host (unconfirmed)")
                else:
                    score = 40 if ransom else 25
                    reasons.append("matched on a declared tech tag; no host located "
                                   "— patch-awareness only")

            # 2) anything at a company that's on a ransomware leak site
            if company_has_ransom and f["kind"] != "ransomware_mention":
                score += 15
                reasons.append("company is currently on a ransomware leak site")

            # 3) a cert-log host that a scanner has confirmed is live & exposed
            if f["kind"] == "certificate_host":
                host = detail.get("host", "").lower()
                if host in exposed_hosts:
                    score += 25
                    reasons.append("newly-seen host is also internet-exposed")

            # 4) breach / leaked-credential exposure at a company that also has an
            #    exposed remote-access service -> that's a path straight in
            if f["kind"] in ("breach", "breached_accounts", "credential_leak"):
                exposed_remote = any(i.get("detail", {}).get("risky_service")
                                     for i in items)
                has_creds = detail.get("has_passwords")
                if exposed_remote:
                    score += 15 if has_creds else 10
                    reasons.append(
                        "leaked credentials + exposed remote-access service"
                        if has_creds else
                        "breach exposure + exposed remote-access service")

            # 5) a domain flagged malicious that also exposes services is more
            #    likely a genuinely compromised host than a stray detection
            if f["kind"] == "malicious_verdict":
                if any(i["kind"] == "exposed_service" for i in items):
                    score += 8
                    reasons.append("flagged-malicious domain also has exposed services")

            # --- recency: the feed is about *today* ---------------------------
            if _recent(f.get("first_seen"), days=1):
                score += 10
                reasons.append("new in the last 24h")
            elif _recent(f.get("first_seen"), days=7):
                score += 3
                reasons.append("new this week")

            # --- company criticality multiplier -------------------------------
            crit = companies[company].criticality if company in companies else 1.0
            if crit != 1.0:
                score *= crit
                reasons.append(f"crown-jewel weighting x{crit:g}")

            f["score"] = round(min(max(score, 0), 100), 1)
            f["score_reasons"] = reasons
            f["severity"] = severity_label(f["score"])

    return findings
