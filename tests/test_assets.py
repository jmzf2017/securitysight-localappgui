"""Tests for asset location and KEV/vuln -> host correlation (pcrm/assets.py)."""

from pcrm.assets import locator, product_terms, enrich_assets


def f(company="Acme", source="Shodan", kind="exposed_service", title="t",
      detail=None, evidence_url=None):
    return {"company": company, "source": source, "kind": kind, "title": title,
            "detail": detail or {}, "evidence_url": evidence_url}


# ---------------------------------------------------------------- locator
def test_locator_host_with_ip_port_fqdns():
    loc = locator(f(detail={"ip": "1.2.3.4", "port": 443,
                            "hostnames": ["mail.acme.com", "owa.acme.com"]}))
    assert loc["ip"] == "1.2.3.4" and loc["port"] == 443
    assert loc["fqdns"] == ["mail.acme.com", "owa.acme.com"]


def test_locator_cert_host():
    loc = locator(f(kind="certificate_host", detail={"host": "vpn.acme.com"}))
    assert loc["fqdns"] == ["vpn.acme.com"]
    assert "ip" not in loc


def test_locator_domain_level():
    loc = locator(f(kind="breach", detail={"domain": "acme.com"}))
    assert loc["fqdns"] == ["acme.com"]


def test_locator_dedupes_fqdns():
    loc = locator(f(detail={"hostnames": ["a.acme.com", "a.acme.com"],
                            "host": "a.acme.com"}))
    assert loc["fqdns"] == ["a.acme.com"]


def test_locator_no_host_only_url():
    loc = locator(f(kind="kev_product_match", detail={"product": "Exchange"},
                    evidence_url="https://nvd.example/CVE"))
    assert "ip" not in loc and "fqdns" not in loc
    assert loc["url"].startswith("https://")


# ---------------------------------------------------------------- product_terms
def test_product_terms_exchange_expands_aliases():
    terms = product_terms("Exchange Server")
    assert {"exchange", "owa", "autodiscover", "mail"} <= terms
    assert "server" not in terms      # generic token dropped


def test_product_terms_from_matched_tags():
    assert "forti" in product_terms("", "", "fortinet")


# ---------------------------------------------------------------- enrich_assets
def test_enrich_sets_location_on_every_finding():
    items = [f(detail={"ip": "1.1.1.1", "port": 22})]
    enrich_assets(items)
    assert items[0]["detail"]["location"]["ip"] == "1.1.1.1"


def test_enrich_correlates_kev_to_exposed_host():
    kev = f(kind="kev_product_match", source="NVD-KEV",
            detail={"product": "Exchange Server", "matched_tags": ["exchange"]})
    host = f(kind="exposed_service", source="Shodan",
             detail={"ip": "5.5.5.5", "port": 443, "product": "Microsoft Exchange",
                     "hostnames": ["mail.acme.com"]})
    enrich_assets([kev, host])
    aa = kev["detail"]["affected_assets"]
    assert len(aa) == 1
    assert aa[0]["fqdn"] == "mail.acme.com" and aa[0]["ip"] == "5.5.5.5"
    assert aa[0]["exposed"] is True


def test_enrich_includes_cert_candidate_and_sorts_exposed_first():
    kev = f(kind="kev_product_match",
            detail={"product": "Exchange Server", "matched_tags": ["exchange"]})
    cert = f(kind="certificate_host", source="crt.sh",
             detail={"host": "autodiscover.acme.com"})
    host = f(kind="exposed_service", source="Shodan",
             detail={"ip": "5.5.5.5", "port": 443, "hostnames": ["mail.acme.com"]})
    enrich_assets([kev, cert, host])
    aa = kev["detail"]["affected_assets"]
    assert len(aa) == 2
    assert aa[0]["exposed"] is True            # exposed sorted first
    assert any(a["fqdn"] == "autodiscover.acme.com" and not a["exposed"] for a in aa)


def test_enrich_no_match_gives_empty_list():
    kev = f(kind="kev_product_match",
            detail={"product": "MOVEit Transfer", "matched_tags": ["moveit"]})
    host = f(kind="exposed_service", detail={"ip": "5.5.5.5", "port": 80,
                                             "hostnames": ["www.acme.com"]})
    enrich_assets([kev, host])
    assert kev["detail"]["affected_assets"] == []


def test_enrich_does_not_correlate_across_companies():
    kev = f(company="Acme", kind="kev_product_match",
            detail={"product": "Exchange Server", "matched_tags": ["exchange"]})
    host = f(company="Other", kind="exposed_service",
             detail={"ip": "5.5.5.5", "port": 443, "hostnames": ["mail.other.com"]})
    enrich_assets([kev, host])
    assert kev["detail"]["affected_assets"] == []


def test_enrich_no_affected_assets_key_on_host_kinds():
    host = f(kind="exposed_service", detail={"ip": "1.1.1.1", "port": 443})
    enrich_assets([host])
    assert "affected_assets" not in host["detail"]
    assert "location" in host["detail"]
