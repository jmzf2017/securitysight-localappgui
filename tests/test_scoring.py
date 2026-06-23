"""Tests for the correlation/scoring engine (pcrm/scoring.py).

Recency is excluded from correlation tests by giving findings an old first_seen,
so the arithmetic is exact; recency has its own tests. The KEV catalog is
controlled via monkeypatch (an autouse fixture defaults it to empty so on-disk
state never leaks into a test).
"""

from datetime import datetime, timezone, timedelta

import pytest

from pcrm.scoring import score_all
from pcrm.models import Company, severity_label
from pcrm.collectors.virustotal import verdict_severity, top_flagging_engines

OLD = "2020-01-01T00:00:00+00:00"


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def days_ago(n):
    return (datetime.now(timezone.utc) - timedelta(days=n)).isoformat()


def finding(company="Acme", source="Shodan", kind="exposed_service", title=None,
            detail=None, base_severity=0.0, first_seen=OLD):
    return {"company": company, "source": source, "kind": kind,
            "title": title or f"{kind}-{source}", "detail": detail or {},
            "base_severity": base_severity, "first_seen": first_seen}


def companies(name="Acme", criticality=1.0):
    return {name: Company(name=name, criticality=criticality)}


def pick(scored, **match):
    for f in scored:
        if all(f.get(k) == v for k, v in match.items()):
            return f
    raise AssertionError(f"no finding matching {match}")


@pytest.fixture(autouse=True)
def _default_no_kev(monkeypatch):
    monkeypatch.setattr("pcrm.scoring.load_cached_catalog", lambda: [])


# --------------------------------------------------------------- base behaviour
def test_base_severity_passthrough(monkeypatch):
    f = finding(kind="note", base_severity=30)
    out = score_all([f], companies())[0]
    assert out["score"] == 30
    assert out["severity"] == "low"
    assert out["score_reasons"] == []


def test_score_is_clamped_to_100(monkeypatch):
    monkeypatch.setattr("pcrm.scoring.load_cached_catalog",
                        lambda: [{"cveID": "CVE-R", "knownRansomwareCampaignUse": "Known"}])
    f = finding(kind="exposed_service", base_severity=60,
                detail={"_id": "1.1.1.1:443", "vulns": ["CVE-R"]})
    out = score_all([f], companies(criticality=2.0))[0]
    assert out["score"] == 100  # 97 * 2.0, clamped
    assert out["severity"] == "critical"


# --------------------------------------------------------------- KEV correlation
def test_kev_exposed_service_escalates(monkeypatch):
    monkeypatch.setattr("pcrm.scoring.load_cached_catalog",
                        lambda: [{"cveID": "CVE-1", "knownRansomwareCampaignUse": "Unknown"}])
    f = finding(kind="exposed_service", base_severity=70,
                detail={"_id": "1.1.1.1:443", "vulns": ["CVE-1"]})
    out = score_all([f], companies())[0]
    assert out["score"] == 90
    assert out["severity"] == "critical"
    assert any("actively-exploited KEV" in r for r in out["score_reasons"])


def test_kev_ransomware_linked_maxes_out(monkeypatch):
    monkeypatch.setattr("pcrm.scoring.load_cached_catalog",
                        lambda: [{"cveID": "CVE-R", "knownRansomwareCampaignUse": "Known"}])
    f = finding(kind="exposed_service", base_severity=60,
                detail={"_id": "1.1.1.1:443", "vulns": ["CVE-R"]})
    out = score_all([f], companies())[0]
    assert out["score"] == 97
    assert any("ransomware-linked KEV" in r for r in out["score_reasons"])


def test_non_kev_vuln_does_not_escalate(monkeypatch):
    f = finding(kind="exposed_service", base_severity=40,
                detail={"_id": "1.1.1.1:443", "vulns": ["CVE-9999"]})
    out = score_all([f], companies())[0]
    assert out["score"] == 40
    assert not any("KEV" in r for r in out["score_reasons"])


# ----------------------------------------------------------- multi-scanner agree
def test_multiple_scanners_corroborate(monkeypatch):
    a = finding(source="Shodan", base_severity=30, detail={"_id": "9.9.9.9:22"})
    b = finding(source="Censys", base_severity=30, detail={"_id": "9.9.9.9:22"})
    out = score_all([a, b], companies())
    for f in out:
        assert f["score"] == 36  # 30 + 6
        assert any("multiple scanners" in r for r in f["score_reasons"])


def test_single_scanner_no_corroboration(monkeypatch):
    f = finding(source="Shodan", base_severity=30, detail={"_id": "9.9.9.9:22"})
    out = score_all([f], companies())[0]
    assert out["score"] == 30
    assert not any("multiple scanners" in r for r in out["score_reasons"])


# --------------------------------------------------------- ransomware-on-leaksite
def test_ransomware_company_boosts_other_findings(monkeypatch):
    mention = finding(kind="ransomware_mention", source="RansomLook",
                      base_severity=95, detail={"_id": "Acme:LockBit"})
    exposed = finding(kind="exposed_service", base_severity=30,
                      detail={"_id": "2.2.2.2:80"})
    out = score_all([mention, exposed], companies())
    e = pick(out, kind="exposed_service")
    assert e["score"] == 45  # 30 + 15
    assert any("ransomware leak site" in r for r in e["score_reasons"])


def test_ransomware_mention_not_self_boosted(monkeypatch):
    mention = finding(kind="ransomware_mention", base_severity=95,
                      detail={"_id": "Acme:LockBit"})
    out = score_all([mention], companies())[0]
    assert out["score"] == 95  # no self-boost
    assert not any("ransomware leak site" in r for r in out["score_reasons"])


# --------------------------------------------------------- cert host <-> exposure
def test_certificate_host_confirmed_exposed_escalates(monkeypatch):
    exposed = finding(kind="exposed_service", base_severity=30,
                      detail={"_id": "3.3.3.3:443", "hostnames": ["vpn.acme.com"]})
    cert = finding(kind="certificate_host", source="crt.sh", base_severity=10,
                   detail={"_id": "vpn.acme.com", "host": "vpn.acme.com"})
    out = score_all([exposed, cert], companies())
    c = pick(out, kind="certificate_host")
    assert c["score"] == 35  # 10 + 25
    assert any("internet-exposed" in r for r in c["score_reasons"])


def test_certificate_host_without_overlap_stays_low(monkeypatch):
    cert = finding(kind="certificate_host", source="crt.sh", base_severity=10,
                   detail={"_id": "blog.acme.com", "host": "blog.acme.com"})
    out = score_all([cert], companies())[0]
    assert out["score"] == 10
    assert out["severity"] == "info"


# ------------------------------------------------- breach / creds + remote access
def test_breach_plus_remote_access(monkeypatch):
    exposed = finding(kind="exposed_service", base_severity=60,
                      detail={"_id": "4.4.4.4:3389", "risky_service": "RDP"})
    breach = finding(kind="breach", source="Mallory-Breaches", base_severity=55,
                     detail={"_id": "acme:b1"})
    out = score_all([exposed, breach], companies())
    b = pick(out, kind="breach")
    assert b["score"] == 65  # 55 + 10 (no passwords flag)
    assert any("remote-access" in r for r in b["score_reasons"])


def test_credential_leak_with_passwords_plus_remote(monkeypatch):
    exposed = finding(kind="exposed_service", base_severity=60,
                      detail={"_id": "4.4.4.4:3389", "risky_service": "RDP"})
    leak = finding(kind="credential_leak", source="Leak-Lookup", base_severity=68,
                   detail={"_id": "acme:src", "has_passwords": True})
    out = score_all([exposed, leak], companies())
    lk = pick(out, kind="credential_leak")
    assert lk["score"] == 83  # 68 + 15 (passwords)
    assert any("leaked credentials" in r for r in lk["score_reasons"])


def test_breached_accounts_without_remote_no_boost(monkeypatch):
    f = finding(kind="breached_accounts", source="HaveIBeenPwned", base_severity=60,
                detail={"_id": "acme:Collection1", "has_passwords": True})
    out = score_all([f], companies())[0]
    assert out["score"] == 60
    assert not any("remote-access" in r for r in out["score_reasons"])


# ------------------------------------------------------ malicious verdict + exposure
def test_malicious_verdict_with_exposure(monkeypatch):
    verdict = finding(kind="malicious_verdict", source="VirusTotal", base_severity=89,
                      detail={"_id": "acme:reputation"})
    exposed = finding(kind="exposed_service", base_severity=30,
                      detail={"_id": "5.5.5.5:80"})
    out = score_all([verdict, exposed], companies())
    v = pick(out, kind="malicious_verdict")
    assert v["score"] == 97  # 89 + 8
    assert any("flagged-malicious domain" in r for r in v["score_reasons"])


def test_malicious_verdict_without_exposure(monkeypatch):
    f = finding(kind="malicious_verdict", source="VirusTotal", base_severity=89,
                detail={"_id": "acme:reputation"})
    out = score_all([f], companies())[0]
    assert out["score"] == 89
    assert not any("flagged-malicious domain" in r for r in f["score_reasons"])


# --------------------------------------------------------------------- recency
def test_recency_new_today(monkeypatch):
    f = finding(kind="note", base_severity=30, first_seen=now_iso())
    out = score_all([f], companies())[0]
    assert out["score"] == 40  # +10
    assert any("last 24h" in r for r in out["score_reasons"])


def test_recency_new_this_week(monkeypatch):
    f = finding(kind="note", base_severity=30, first_seen=days_ago(3))
    out = score_all([f], companies())[0]
    assert out["score"] == 33  # +3
    assert any("new this week" in r for r in out["score_reasons"])


def test_recency_old_no_boost(monkeypatch):
    f = finding(kind="note", base_severity=30, first_seen=OLD)
    out = score_all([f], companies())[0]
    assert out["score"] == 30
    assert not any("24h" in r or "week" in r for r in out["score_reasons"])


# ----------------------------------------------------------------- criticality
def test_criticality_multiplier(monkeypatch):
    f = finding(kind="note", base_severity=40)
    out = score_all([f], companies(criticality=1.5))[0]
    assert out["score"] == 60  # 40 * 1.5
    assert any("crown-jewel weighting x1.5" in r for r in out["score_reasons"])


def test_unknown_company_defaults_criticality_one(monkeypatch):
    f = finding(company="Ghost", kind="note", base_severity=40)
    out = score_all([f], companies())[0]  # "Ghost" not in map
    assert out["score"] == 40


# ----------------------------------------------------------- severity label bands
@pytest.mark.parametrize("score,label", [
    (95, "critical"), (90, "critical"), (89.9, "high"), (70, "high"),
    (69, "medium"), (40, "medium"), (39, "low"), (15, "low"),
    (14, "info"), (0, "info"),
])
def test_severity_label_boundaries(score, label):
    assert severity_label(score) == label


# ---------------------------------------------------- VirusTotal verdict severity
def test_verdict_clean_emits_nothing():
    assert verdict_severity(0, 0, 5) == (False, 0.0, "clean")
    assert verdict_severity(0, 1, 0) == (False, 0.0, "clean")


def test_verdict_malicious():
    emit, score, label = verdict_severity(6, 2, -34)
    assert emit and label == "malicious" and score == 95  # 55+35 cap, +5 rep


def test_verdict_suspicious_only():
    assert verdict_severity(0, 3, 0) == (True, 52, "suspicious")


def test_verdict_poor_reputation_only():
    assert verdict_severity(0, 0, -25) == (True, 40, "poor-reputation")


def test_top_flagging_engines_filters_and_sorts():
    res = top_flagging_engines({"A": {"category": "malicious"},
                                "B": {"category": "harmless"},
                                "C": {"category": "suspicious"}})
    assert res == ["A", "C"]


# ------------------------------------- product/inventory match scored by evidence
def test_product_match_tag_only_is_not_critical(monkeypatch):
    # KEV matched on a tag, ransomware-linked, but NO host located -> awareness
    f = finding(kind="kev_product_match", source="NVD-KEV", base_severity=40,
                detail={"product": "Exchange Server", "ransomware_use": "Known",
                        "affected_assets": []})
    out = score_all([f], companies())[0]
    assert out["score"] == 40 and out["severity"] == "medium"
    assert any("patch-awareness only" in r for r in out["score_reasons"])


def test_product_match_tag_only_non_ransom_is_low(monkeypatch):
    f = finding(kind="kev_product_match", base_severity=25,
                detail={"product": "Apache httpd", "ransomware_use": "Unknown",
                        "affected_assets": []})
    out = score_all([f], companies())[0]
    assert out["score"] == 25 and out["severity"] == "low"


def test_product_match_with_exposed_host_is_critical(monkeypatch):
    f = finding(kind="kev_product_match", base_severity=40,
                detail={"product": "Exchange Server", "ransomware_use": "Known",
                        "affected_assets": [{"fqdn": "mail.acme.com", "ip": "5.5.5.5",
                                             "port": 443, "exposed": True}]})
    out = score_all([f], companies())[0]
    assert out["score"] == 97 and out["severity"] == "critical"
    assert any("internet-exposed host" in r for r in out["score_reasons"])


def test_product_match_with_candidate_host_is_mid(monkeypatch):
    f = finding(kind="kev_product_match", base_severity=40,
                detail={"product": "Exchange Server", "ransomware_use": "Known",
                        "affected_assets": [{"fqdn": "autodiscover.acme.com",
                                             "exposed": False}]})
    out = score_all([f], companies())[0]
    assert out["score"] == 65   # candidate, ransomware-linked
    assert any("candidate host" in r for r in out["score_reasons"])
