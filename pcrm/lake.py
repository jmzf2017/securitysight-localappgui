"""Data lake — now backed by SQLite (see pcrm/store.py).

The public API is unchanged from the JSONL/state.json era so the pipeline,
scoring, assets and dashboard don't have to change:

  ingest(findings) -> {"new": [...], "recurring": [...]}
  all_findings() -> list[dict]      (live references; mutations persist on save)
  get(fp) -> dict | None
  set_triage(fp, status, note)
  rescore(scored)

Like the old Lake it keeps the current state in memory and writes the whole
state back on save. That in-memory model is load-bearing: the pipeline calls
all_findings() to enrich (mutating detail in place) and again to score, relying
on both calls returning the *same* dict objects. We preserve that exactly.
"""

from __future__ import annotations

import shutil
from datetime import datetime
from pathlib import Path
from typing import Iterable

from .models import Finding, utcnow_iso
from .store import Store, db_path


class Lake:
    def __init__(self, store_or_root: "Store | str | Path" = "data"):
        if isinstance(store_or_root, Store):
            self.store = store_or_root
            self.root = self.store.path.parent
        else:
            self.root = Path(store_or_root)
            self.store = Store(db_path(self.root))
        self._state: dict[str, dict] = self.store.load_state()

    # ---------------------------------------------------------------- ingest
    def ingest(self, findings: Iterable[Finding]) -> dict[str, list[Finding]]:
        """Append findings to the audit log and merge into current state.

        Returns {"new": [...], "recurring": [...]} so the pipeline can alert
        only on genuinely new things.
        """
        run_ts = utcnow_iso()
        run_id = self.store.next_run_id()
        new, recurring = [], []

        for f in findings:
            fp = f.fingerprint
            prior = self._state.get(fp)
            if prior is None:
                f.first_seen = run_ts
                f.last_seen = run_ts
                self._state[fp] = {
                    **f.to_dict(),
                    "triage": "new",            # new | acknowledged | dismissed
                    "triage_note": "",
                    "triage_at": None,
                }
                new.append(f)
            else:
                f.first_seen = prior["first_seen"]
                f.last_seen = run_ts
                # preserve human triage decisions across runs
                self._state[fp].update(
                    {**f.to_dict(),
                     "triage": prior.get("triage", "new"),
                     "triage_note": prior.get("triage_note", ""),
                     "triage_at": prior.get("triage_at")}
                )
                recurring.append(f)

            # immutable append — full record every time
            self.store.insert_observation(run_id, run_ts, f.to_dict())

        self._persist()
        return {"new": new, "recurring": recurring}

    # ---------------------------------------------------------------- read
    def all_findings(self) -> list[dict]:
        return list(self._state.values())

    def get(self, fingerprint: str) -> dict | None:
        return self._state.get(fingerprint)

    def set_triage(self, fingerprint: str, status: str, note: str = "") -> bool:
        rec = self._state.get(fingerprint)
        if not rec:
            return False
        rec["triage"] = status
        rec["triage_note"] = note
        rec["triage_at"] = utcnow_iso()
        self.store.upsert_finding(rec)
        self.store.commit()
        return True

    def rescore(self, scored: list[dict]) -> None:
        """Write recomputed scores (and any enrichment that mutated the shared
        records) back to the store. Scoring runs over the whole lake each pass."""
        for rec in scored:
            fp = rec["fingerprint"]
            if fp in self._state:
                self._state[fp]["score"] = rec["score"]
                self._state[fp]["score_reasons"] = rec.get("score_reasons", [])
                self._state[fp]["severity"] = rec["severity"]
        self._persist()

    # ---------------------------------------------------------------- internal
    def _persist(self) -> None:
        """Upsert the full current state (mirrors the old whole-file save, so
        in-place enrichment of detail is captured)."""
        self.store.upsert_findings(self._state.values())
        self.store.commit()


def reset_lake(root: str = "data", purge: bool = False) -> dict:
    """Clear the lake so the next run starts fresh.

    Default is recoverable: the lake directory (which now holds the SQLite DB)
    is moved aside to ``<root>.bak.<timestamp>``. With ``purge=True`` it is
    permanently deleted. Either way, all triage state is cleared, since that
    lives in the lake. Returns a dict describing what happened.
    """
    path = Path(root)
    if not path.exists():
        return {"action": "none", "detail": f"no lake found at {path}"}
    if purge:
        shutil.rmtree(path)
        return {"action": "purged", "detail": str(path)}
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = path.parent / f"{path.name}.bak.{ts}"
    shutil.move(str(path), str(dest))
    return {"action": "archived", "detail": str(dest)}
