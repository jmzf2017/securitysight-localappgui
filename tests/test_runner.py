"""Tests for the background RunManager: status lifecycle, the single-run lock,
per-collector status, and run-scoped secret injection. All offline (collectors
are monkeypatched; no network)."""

import threading

import pytest

from pcrm import pipeline
from pcrm.collectors.base import BaseCollector
from pcrm.models import Finding
from pcrm.runner import RunManager, RunInProgress
from pcrm.secrets import SecretStore, MemoryBackend
from pcrm.store import Store, db_path


class DummyOK(BaseCollector):
    NAME = "DummyOK"
    KEY_ENV = ""
    STATUS = "live"

    def collect(self, companies):
        return [Finding(company="Acme", source=self.NAME, kind="exposed_service",
                        title="1.1.1.1:443",
                        detail={"_id": "1.1.1.1:443", "ip": "1.1.1.1", "port": 443})]


class DummyFail(BaseCollector):
    NAME = "DummyFail"
    KEY_ENV = ""
    STATUS = "live"

    def collect(self, companies):
        raise RuntimeError("boom")


def _mgr(tmp_path, store=None):
    return RunManager(data_root=str(tmp_path),
                      secret_store=store or SecretStore(MemoryBackend()))


def test_run_completes_and_records_a_row(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "select", lambda *a, **k: [])
    m = _mgr(tmp_path)
    run_id = m.start(alert=False)
    m.join(5)
    st = m.status()
    assert st["state"] == "done" and st["run_id"] == run_id
    assert st["finished_at"] and st["summary"] is not None
    runs = Store(db_path(tmp_path)).get_runs()
    assert runs and runs[0]["id"] == run_id and runs[0]["status"] == "done"


def test_per_collector_status_is_captured(tmp_path, monkeypatch):
    monkeypatch.setattr(pipeline, "select", lambda *a, **k: [DummyOK, DummyFail])
    m = _mgr(tmp_path)
    m.start(alert=False)
    m.join(5)
    by = {c["name"]: c for c in m.status()["collectors"]}
    assert by["DummyOK"]["status"] == "ok" and by["DummyOK"]["count"] == 1
    assert by["DummyFail"]["status"] == "fail" and "boom" in by["DummyFail"]["error"]
    # one failing collector does not fail the whole run
    assert m.status()["state"] == "done"


def test_single_run_lock(tmp_path, monkeypatch):
    gate = threading.Event()

    def blocking_run(**kw):
        gate.wait(5)
        return {"new": 0, "recurring": 0, "total_in_lake": 0}

    monkeypatch.setattr(pipeline, "run", blocking_run)
    m = _mgr(tmp_path)
    m.start(alert=False)
    with pytest.raises(RunInProgress):
        m.start(alert=False)         # second start rejected while one is running
    gate.set()
    m.join(5)
    assert m.status()["state"] == "done"


def test_secret_is_injected_for_the_run(tmp_path, monkeypatch):
    seen = {}

    def capture_run(**kw):
        import os
        seen["key"] = os.environ.get("SHODAN_API_KEY")
        return {"new": 0, "recurring": 0, "total_in_lake": 0}

    monkeypatch.setattr(pipeline, "run", capture_run)
    store = SecretStore(MemoryBackend())
    store.set("SHODAN_API_KEY", "injected-key")
    m = _mgr(tmp_path, store=store)
    m.start(alert=False)
    m.join(5)
    assert seen["key"] == "injected-key"
    # injection is scoped to the run: env is clean afterwards
    import os
    assert "SHODAN_API_KEY" not in os.environ
