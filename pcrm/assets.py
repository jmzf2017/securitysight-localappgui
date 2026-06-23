"""Asset location & correlation — make findings point at a real system.

Two jobs:

  locator(finding)        -> normalize wherever-it-lives info (ip, port, fqdns)
                             from each collector's detail shape into one shape.
  enrich_assets(findings) -> for product/inventory findings that have no host of
                             their own (a KEV or vuln matched on your tech tags),
                             find the hosts other collectors DID locate that look
                             like that product, and attach them as affected_assets.

So "KEV affects Exchange Server" stops being abstract and becomes "...likely on
mail.acme.com (198.51.100.5:443), seen by Shodan" — or, when nothing public
locates it, an explicit note that it's a tag match to chase in your inventory.
"""

from __future__ import annotations

import re

# Findings that name a product/vendor but carry no host of their own.
PRODUCT_KINDS = {"kev_product_match", "vuln_intel"}
# Findings that locate a real host/FQDN we can correlate against.
HOST_KINDS = {"exposed_service", "certificate_host", "passive_dns"}

# Product/vendor -> the words that show up in banners, services and hostnames.
ALIASES = {
    "exchange": ["exchange", "owa", "outlook", "autodiscover", "webmail", "activesync", "mail"],
    "forti":    ["forti", "fortios", "fortigate", "fortinet", "vpn"],
    "citrix":   ["citrix", "netscaler", "adc"],
    "vmware":   ["vmware", "vcenter", "esxi", "vsphere", "horizon"],
    "moveit":   ["moveit"],
    "ivanti":   ["ivanti", "pulse"],
    "windows":  ["windows", "rdp", "iis"],
    "confluence": ["confluence", "atlassian", "jira"],
    "gitlab":   ["gitlab"],
    "apache":   ["apache", "httpd", "tomcat"],
}
# tokens too generic to match on their own
_GENERIC = {"server", "transfer", "secure", "connect", "systems", "service",
            "software", "the", "and", "for"}


def product_terms(*strings: str) -> set[str]:
    """Build the set of keywords to look for in host data, from a product name,
    vendor, and/or the tags that matched."""
    terms: set[str] = set()
    for s in strings:
        if not s:
            continue
        s = str(s).lower()
        for key, words in ALIASES.items():
            if key in s:
                terms.update(words)
        for tok in re.findall(r"[a-z0-9]+", s):
            if len(tok) >= 3 and tok not in _GENERIC:
                terms.add(tok)
    return terms


def locator(finding: dict) -> dict:
    """Normalize a finding's location info. Returns only the keys it can fill:
    ip, port, fqdns (list), url."""
    d = finding.get("detail", {}) or {}
    loc: dict = {}
    if d.get("ip"):
        loc["ip"] = d["ip"]
    if d.get("port"):
        loc["port"] = d["port"]
    fqdns: list[str] = []
    hn = d.get("hostnames")
    if isinstance(hn, list):
        fqdns.extend(hn)
    for k in ("host", "domain"):
        if d.get(k):
            fqdns.append(d[k])
    # de-dupe, preserve order
    seen, ordered = set(), []
    for h in fqdns:
        hl = str(h).lower()
        if hl and hl not in seen:
            seen.add(hl)
            ordered.append(h)
    if ordered:
        loc["fqdns"] = ordered
    if finding.get("evidence_url"):
        loc["url"] = finding["evidence_url"]
    return loc


def _host_text(h: dict) -> str:
    d = h.get("detail", {}) or {}
    parts = [d.get("product"), d.get("version"), d.get("service"), h.get("title"),
             d.get("host"), " ".join(d.get("hostnames", []) or [])]
    return " ".join(str(p) for p in parts if p).lower()


def _asset(h: dict) -> dict:
    d = h.get("detail", {}) or {}
    fqdn = None
    if d.get("hostnames"):
        fqdn = d["hostnames"][0]
    elif d.get("host"):
        fqdn = d["host"]
    return {"ip": d.get("ip"), "port": d.get("port"), "fqdn": fqdn,
            "source": h.get("source"), "exposed": h.get("kind") == "exposed_service"}


def enrich_assets(findings: list[dict]) -> list[dict]:
    """Mutate findings in place: set detail['location'] on everything, and
    detail['affected_assets'] on product/inventory findings."""
    by_company: dict[str, list[dict]] = {}
    for f in findings:
        by_company.setdefault(f.get("company", ""), []).append(f)

    for items in by_company.values():
        host_findings = [h for h in items if h.get("kind") in HOST_KINDS]
        for f in items:
            detail = f.setdefault("detail", {})
            detail["location"] = locator(f)

            if f.get("kind") not in PRODUCT_KINDS:
                continue

            terms = product_terms(detail.get("product", ""),
                                  detail.get("vendor", ""),
                                  *detail.get("matched_tags", []))
            assets, seen = [], set()
            if terms:
                for h in host_findings:
                    text = _host_text(h)
                    if any(t in text for t in terms):
                        a = _asset(h)
                        key = (a["ip"], a["port"], a["fqdn"])
                        if key not in seen:
                            seen.add(key)
                            assets.append(a)
            # exposed (has an IP) first, then FQDN candidates
            assets.sort(key=lambda a: (not a["exposed"], a["fqdn"] or ""))
            detail["affected_assets"] = assets
    return findings
