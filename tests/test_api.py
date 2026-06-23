"""Tests for the REST API (pcrm/web.py) via Flask's test client.

Uses a temp data root + an in-memory keychain backend + a RunManager we hold a
reference to (so we can join the worker thread); collectors are monkeypatched so
nothing hits the network.
"""

import threading

import pytest

from pcrm import pipeline
from pcrm.models import Finding
from pcrm.runner import RunManager
from pcrm.secrets import SecretStore, MemoryBackend
from pcrm.store import Store, db_path
from pcrm.web import create_app


@pytest.fixture
def ctx(tmp_path):
    secrets = SecretStore(MemoryBackend())
    runs = RunManager(data_root=str(tmp_path), secret_store=secrets)
    app = create_app(data_root=str(tmp_path), secret_store=secrets, run_manager=runs)
    store = Store(db_path(tmp_path))
    return app.test_client(), store, secrets, runs


def _seed_findings(store):
    store.upsert_finding({"fingerprint": "fp1", "company": "Acme", "source": "Shodan",
                          "kind": "exposed_service", "title": "1.1.1.1:3389 (RDP)",
                          "detail": {"ip": "1.1.1.1"}, "score": 95, "severity": "critical",
                          "first_seen": "2026-06-01T00:00:00+00:00", "triage": "new"})
    store.upsert_finding({"fingerprint": "fp2", "company": "Globex", "source": "crt.sh",
                          "kind": "certificate_host", "title": "host in CT",
                          "detail": {}, "score": 20, "severity": "low",
                          "first_seen": "2026-06-01T00:00:00+00:00", "triage": "new"})
    store.commit()


# ---------------------------------------------------------------- findings
def test_findings_filter_paginate(ctx):
    c, store, _, _ = ctx
    _seed_findings(store)
    r = c.get("/api/findings")
    body = r.get_json()
    assert body["total"] == 2 and len(body["items"]) == 2

    r = c.get("/api/findings?severity=critical")
    assert r.get_json()["total"] == 1
    r = c.get("/api/findings?company=Globex")
    assert r.get_json()["items"][0]["fingerprint"] == "fp2"
    r = c.get("/api/findings?q=RDP")
    assert r.get_json()["total"] == 1
    r = c.get("/api/findings?page_size=1&page=1")
    assert len(r.get_json()["items"]) == 1 and r.get_json()["total"] == 2


def test_facets_and_index_render(ctx):
    c, store, _, _ = ctx
    _seed_findings(store)
    f = c.get("/api/facets").get_json()
    assert set(f["companies"]) == {"Acme", "Globex"}
    assert "Shodan" in f["sources"]
    assert f["stats"]["critical_open"] == 1 and f["stats"]["total"] == 2
    # the SPA shell renders with no server-side context (no embedded findings blob)
    html = c.get("/").get_data(as_text=True)
    assert c.get("/").status_code == 200
    assert "tojson" not in html and "/api/findings" in html


def test_triage_updates_and_filters(ctx):
    c, store, _, _ = ctx
    _seed_findings(store)
    assert c.post("/api/triage", json={"fingerprint": "fp1", "status": "dismissed"}).status_code == 200
    # default status filter is 'open' -> dismissed fp1 drops out
    assert c.get("/api/findings?status=open&severity=critical").get_json()["total"] == 0
    assert c.get("/api/findings?status=dismissed").get_json()["total"] == 1
    # missing fingerprint -> 404
    assert c.post("/api/triage", json={"fingerprint": "nope", "status": "x"}).status_code == 404
    assert c.post("/api/triage", json={}).status_code == 400


# ---------------------------------------------------------------- companies
def test_company_crud(ctx):
    c, _, _, _ = ctx
    r = c.post("/api/companies", json={"name": "Acme", "domains": "acme.example, a2.example",
                                       "tags": ["nginx"], "criticality": 1.4})
    assert r.status_code == 201
    cid = r.get_json()["id"]
    listing = c.get("/api/companies").get_json()
    assert listing[0]["name"] == "Acme" and listing[0]["domains"] == ["acme.example", "a2.example"]

    assert c.post("/api/companies", json={"name": "Acme"}).status_code == 409   # dup
    assert c.post("/api/companies", json={"name": ""}).status_code == 400        # invalid

    assert c.put(f"/api/companies/{cid}", json={"name": "Acme", "criticality": 2.0}).status_code == 200
    assert c.get("/api/companies").get_json()[0]["criticality"] == 2.0
    assert c.delete(f"/api/companies/{cid}").status_code == 200
    assert c.get("/api/companies").get_json() == []
    assert c.delete("/api/companies/999").status_code == 404


# ---------------------------------------------------------------- settings
def test_settings_get_put(ctx):
    c, _, _, _ = ctx
    assert c.put("/api/settings", json={"alert_min_severity": "medium"}).status_code == 200
    assert c.get("/api/settings").get_json()["alert_min_severity"] == "medium"


# ---------------------------------------------------------------- keys
def test_keys_never_leak_values_and_validate(ctx):
    c, store, secrets, _ = ctx
    assert c.put("/api/keys/SHODAN_API_KEY", json={"value": "supersecret"}).status_code == 200
    keys = {k["name"]: k for k in c.get("/api/keys").get_json()}
    assert keys["SHODAN_API_KEY"]["set"] is True
    # the secret value must never appear in any key listing
    assert "supersecret" not in c.get("/api/keys").get_data(as_text=True)

    # validate a Slack webhook by format; result is recorded
    r = c.post("/api/keys/SLACK_WEBHOOK_URL/validate",
               json={"value": "https://hooks.slack.com/services/x"})
    assert r.get_json()["ok"] is True
    assert c.get("/api/keys") and {k["name"]: k for k in c.get("/api/keys").get_json()}["SLACK_WEBHOOK_URL"]["validated_at"]

    assert c.put("/api/keys/NOPE", json={"value": "x"}).status_code == 404
    assert c.put("/api/keys/SHODAN_API_KEY", json={}).status_code == 400
    assert c.delete("/api/keys/SHODAN_API_KEY").status_code == 200
    assert {k["name"]: k for k in c.get("/api/keys").get_json()}["SHODAN_API_KEY"]["set"] is False


# ---------------------------------------------------------------- runs
def test_run_lifecycle(ctx, monkeypatch):
    c, store, _, runs = ctx
    monkeypatch.setattr(pipeline, "select", lambda *a, **k: [])   # no collectors, offline
    r = c.post("/api/run", json={"no_alert": True})
    assert r.status_code == 202
    run_id = r.get_json()["run_id"]
    runs.join(5)
    assert c.get("/api/run/status").get_json()["state"] == "done"
    history = c.get("/api/runs").get_json()
    assert history and history[0]["id"] == run_id and history[0]["status"] == "done"


def test_run_conflict_when_busy(ctx, monkeypatch):
    c, _, _, runs = ctx
    gate = threading.Event()
    monkeypatch.setattr(pipeline, "run",
                        lambda **kw: (gate.wait(5), {"new": 0, "recurring": 0,
                                                     "total_in_lake": 0})[1])
    runs.start(alert=False)                      # occupy the single-run lock
    try:
        assert c.post("/api/run", json={}).status_code == 409
    finally:
        gate.set()
        runs.join(5)


# ---------------------------------------------------------------- config io
def test_export_import_roundtrip(ctx):
    c, _, _, _ = ctx
    c.post("/api/companies", json={"name": "Acme", "domains": ["acme.example"]})
    exported = c.get("/api/export").get_json()
    assert "Acme" in exported["companies"]

    r = c.post("/api/import", json={"companies":
               "companies:\n  - name: Globex\n    domains: [globex.example]\n"})
    assert r.status_code == 200
    names = [x["name"] for x in c.get("/api/companies").get_json()]
    assert names == ["Globex"]                   # import replaces


def test_version(ctx):
    c, _, _, _ = ctx
    assert "current" in c.get("/api/version").get_json()


def test_version_check_offline_then_mocked(ctx, monkeypatch):
    c, _, _, _ = ctx
    v = c.get("/api/version").get_json()
    assert v["current"] and v["latest"] is None        # no network without ?check
    monkeypatch.setattr("pcrm.web._latest_version", lambda: "9.9.9")
    v2 = c.get("/api/version?check=1").get_json()
    assert v2["latest"] == "9.9.9" and v2["update_url"]


def test_onboarding_state_and_complete(ctx):
    c, _, _, _ = ctx
    assert c.get("/api/onboarding/state").get_json()["needed"] is True   # empty
    assert c.post("/api/onboarding/complete").get_json()["ok"] is True
    assert c.get("/api/onboarding/state").get_json()["needed"] is False


def test_onboarding_not_needed_once_configured(ctx):
    c, _, secrets, _ = ctx
    c.post("/api/companies", json={"name": "Acme"})      # a watchlist entry counts
    assert c.get("/api/onboarding/state").get_json()["needed"] is False


def test_seed_demo_endpoint(ctx, tmp_path, monkeypatch):
    c, _, _, _ = ctx
    from pcrm.collectors import cisa_kev
    # keep the demo KEV cache out of the repo's data/ dir
    monkeypatch.setattr(cisa_kev, "CACHE", tmp_path / "cache" / "kev.json")
    body = c.post("/api/seed-demo").get_json()
    assert body["ok"] and body["total"] > 0
    assert c.get("/api/findings").get_json()["total"] > 0
    # the index page renders with seeded data
    assert c.get("/").status_code == 200
