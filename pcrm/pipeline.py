"""The daily pipeline: collect -> ingest -> score -> alert.

Kept separate from the CLI so it can also be driven from cron, a notebook, or
tests. Returns a summary dict.
"""

from __future__ import annotations

import sys
import time

from .config import ensure_config_seeded
from .lake import Lake
from .store import Store, db_path
from .registry import select
from .scoring import score_all
from .assets import enrich_assets
from .notify import slack


def _emit(on_event, event: dict) -> None:
    """Best-effort progress callback; a misbehaving listener can't sink the run."""
    if on_event:
        try:
            on_event(event)
        except Exception:  # noqa: BLE001
            pass


def run(collector_filter: str | None = None, *,
        cadence: str | None = None,
        companies_path: str = "config/companies.yaml",
        settings_path: str = "config/settings.yaml",
        data_root: str = "data",
        alert: bool = True,
        dry_run: bool = False,
        on_event=None) -> dict:
    store = Store(db_path(data_root))
    # first run / existing CLI users: seed the store from YAML if it's empty
    ensure_config_seeded(store, companies_path, settings_path)
    settings = store.get_settings()
    companies = store.get_companies()
    company_map = {c.name: c for c in companies}
    lake = Lake(store)

    collectors = select(collector_filter, cadence)
    ran, skipped, all_findings = [], [], []
    _emit(on_event, {"type": "run_start", "collectors": [c.NAME for c in collectors]})

    for cls in collectors:
        c = cls()
        if not c.ready:
            why = "stub" if c.STATUS == "stub" else f"missing {c.KEY_ENV}"
            skipped.append((c.NAME, why))
            print(f"  skip  {c.NAME:<16} ({why})", file=sys.stderr)
            _emit(on_event, {"type": "collector", "name": c.NAME,
                             "status": "skip", "reason": why})
            continue
        t0 = time.time()
        try:
            found = c.collect(companies)
        except Exception as e:  # noqa: BLE001 - one collector can't sink the run
            print(f"  FAIL  {c.NAME:<16} {e}", file=sys.stderr)
            skipped.append((c.NAME, f"error: {e}"))
            _emit(on_event, {"type": "collector", "name": c.NAME,
                             "status": "fail", "error": str(e)})
            continue
        all_findings.extend(found)
        ran.append(c.NAME)
        print(f"  ok    {c.NAME:<16} {len(found):>4} findings "
              f"({time.time()-t0:.1f}s)", file=sys.stderr)
        _emit(on_event, {"type": "collector", "name": c.NAME, "status": "ok",
                         "count": len(found), "seconds": round(time.time() - t0, 1)})

    # ingest (diff new vs recurring); locate/correlate hosts FIRST so scoring can
    # tell a tag-only match from one backed by a real exposed host; then score.
    _emit(on_event, {"type": "phase", "name": "ingest"})
    result = lake.ingest(all_findings)
    _emit(on_event, {"type": "phase", "name": "enrich"})
    enrich_assets(lake.all_findings())
    _emit(on_event, {"type": "phase", "name": "score"})
    scored = score_all(lake.all_findings(), company_map)
    lake.rescore(scored)

    # re-read new findings with their freshly-computed scores
    new_scored = [lake.get(f.fingerprint) for f in result["new"]]
    new_scored = [f for f in new_scored if f]

    alert_result = {"sent": 0, "reason": "alerting disabled"}
    if alert:
        _emit(on_event, {"type": "phase", "name": "alert"})
        alert_result = slack.post_new_findings(
            new_scored,
            min_severity=settings.get("alert_min_severity", "high"),
            dashboard_url=settings.get("dashboard_url", "http://localhost:8000"),
            dry_run=dry_run,
        )

    summary = {
        "ran": ran,
        "skipped": skipped,
        "new": len(result["new"]),
        "recurring": len(result["recurring"]),
        "total_in_lake": len(lake.all_findings()),
        "alert": alert_result,
    }
    _emit(on_event, {"type": "run_done", "summary": summary})
    return summary
