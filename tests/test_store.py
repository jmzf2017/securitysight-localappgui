"""Tests for the SQLite store + the Lake facade over it (pcrm/store.py, pcrm/lake.py).

Covers the behaviours the rest of the system relies on: ingest new vs recurring,
triage persistence across reloads, score + in-place enrichment persistence, the
append-only guarantee on observations, and the config (companies/settings) store.
"""

import sqlite3
import tempfile
from pathlib import Path

import pytest

from pcrm.models import Company, Finding
from pcrm.store import Store, db_path
from pcrm.lake import Lake
from pcrm.config import ensure_config_seeded, import_config_yaml, export_config_yaml


def _finding(company="Acme", source="Shodan", kind="exposed_service",
             title="1.2.3.4:443", detail=None):
    return Finding(company=company, source=source, kind=kind, title=title,
                   detail=detail or {"_id": title}, base_severity=30)


@pytest.fixture
def lake(tmp_path):
    return Lake(Store(db_path(tmp_path)))


# ---------------------------------------------------------------- ingest
def test_ingest_new_then_recurring(lake):
    r1 = lake.ingest([_finding(), _finding(title="5.6.7.8:22")])
    assert len(r1["new"]) == 2 and len(r1["recurring"]) == 0
    assert len(lake.all_findings()) == 2

    r2 = lake.ingest([_finding()])               # same fingerprint -> recurring
    assert len(r2["new"]) == 0 and len(r2["recurring"]) == 1
    assert len(lake.all_findings()) == 2          # no duplicate row


def test_ingest_appends_observations_every_run(tmp_path):
    store = Store(db_path(tmp_path))
    lake = Lake(store)
    lake.ingest([_finding()])
    lake.ingest([_finding()])                     # recurring, but still logged
    n = store.conn.execute("SELECT COUNT(*) c FROM observations").fetchone()["c"]
    assert n == 2


# ---------------------------------------------------------------- persistence
def test_triage_persists_across_reload(tmp_path):
    store = Store(db_path(tmp_path))
    lake = Lake(store)
    [f] = lake.ingest([_finding()])["new"]
    assert lake.set_triage(f.fingerprint, "acknowledged", "looked at it")

    reloaded = Lake(Store(db_path(tmp_path)))
    rec = reloaded.get(f.fingerprint)
    assert rec["triage"] == "acknowledged"
    assert rec["triage_note"] == "looked at it"


def test_rescore_and_inplace_enrichment_persist(tmp_path):
    """The pipeline enriches detail in place via all_findings() then rescores;
    both must survive a save+reload (the old whole-state-save property)."""
    store = Store(db_path(tmp_path))
    lake = Lake(store)
    [f] = lake.ingest([_finding()])["new"]

    recs = lake.all_findings()                    # live references
    recs[0]["detail"]["location"] = {"ip": "1.2.3.4", "port": 443}   # enrichment
    recs[0]["score"] = 91
    recs[0]["severity"] = "critical"
    recs[0]["score_reasons"] = ["exposed service runs KEV CVE"]
    lake.rescore(recs)

    rec = Lake(Store(db_path(tmp_path))).get(f.fingerprint)
    assert rec["score"] == 91 and rec["severity"] == "critical"
    assert rec["detail"]["location"] == {"ip": "1.2.3.4", "port": 443}
    assert rec["score_reasons"] == ["exposed service runs KEV CVE"]


def test_record_shape_matches_old_lake(lake):
    [f] = lake.ingest([_finding()])["new"]
    rec = lake.get(f.fingerprint)
    # the dict scoring/assets/dashboard consume
    for key in ("fingerprint", "company", "source", "kind", "title", "detail",
                "score", "severity", "score_reasons", "triage", "first_seen"):
        assert key in rec
    assert isinstance(rec["detail"], dict)
    assert isinstance(rec["score_reasons"], list)


# ---------------------------------------------------------------- audit guarantee
def test_observations_are_append_only(tmp_path):
    store = Store(db_path(tmp_path))
    Lake(store).ingest([_finding()])
    with pytest.raises(sqlite3.IntegrityError):
        store.conn.execute("UPDATE observations SET title='x'")
    with pytest.raises(sqlite3.IntegrityError):
        store.conn.execute("DELETE FROM observations")


# ---------------------------------------------------------------- config store
def test_companies_and_settings_roundtrip(tmp_path):
    store = Store(db_path(tmp_path))
    store.replace_companies([
        Company(name="Acme", domains=["acme.example"], tags=["nginx"], criticality=1.4),
    ])
    store.replace_settings({"alert_min_severity": "high"})

    got = store.get_companies()
    assert len(got) == 1 and got[0].name == "Acme"
    assert got[0].domains == ["acme.example"] and got[0].criticality == 1.4
    assert store.get_settings()["alert_min_severity"] == "high"


def test_ensure_config_seeded_imports_yaml_once(tmp_path):
    cfg = tmp_path / "companies.yaml"
    cfg.write_text("companies:\n  - name: Demo\n    domains: [demo.example]\n")
    settings = tmp_path / "settings.yaml"
    settings.write_text("alert_min_severity: medium\n")
    store = Store(db_path(tmp_path / "data"))

    ensure_config_seeded(store, cfg, settings)
    assert store.count_companies() == 1
    assert store.get_settings()["alert_min_severity"] == "medium"

    # idempotent: a second call doesn't duplicate
    ensure_config_seeded(store, cfg, settings)
    assert store.count_companies() == 1


def test_export_config_yaml_roundtrips(tmp_path):
    store = Store(db_path(tmp_path / "data"))
    store.replace_companies([Company(name="Acme", domains=["acme.example"])])
    store.replace_settings({"alert_min_severity": "low"})
    cfg = tmp_path / "out_companies.yaml"
    settings = tmp_path / "out_settings.yaml"
    export_config_yaml(store, cfg, settings)

    store2 = Store(db_path(tmp_path / "data2"))
    import_config_yaml(store2, cfg, settings)
    assert [c.name for c in store2.get_companies()] == ["Acme"]
    assert store2.get_settings()["alert_min_severity"] == "low"
