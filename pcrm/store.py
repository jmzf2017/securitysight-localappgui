"""SQLite store — the single persistence layer for securitysight (v0.4.0).

Replaces the JSONL + state.json lake with one SQLite database, while keeping the
properties that made the old design good:

  observations   append-only audit trail (insert-only; UPDATE/DELETE blocked by
                 triggers). This is the "diff any two days" source of truth that
                 used to be data/observations/*.jsonl.
  findings       derived current state, one row per fingerprint (was state.json):
                 merged record + first_seen/last_seen + score + triage.
  companies      the watchlist (was config/companies.yaml).
  settings       the simple knobs (was config/settings.yaml).

JSON-shaped columns (detail, score_reasons, the list fields on companies) are
stored as JSON text and (de)serialized at the boundary, so the dicts handed to
scoring / assets / the dashboard look exactly like the old lake records.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable

from .models import Company, utcnow_iso

SCHEMA_VERSION = 1

_DDL = """
CREATE TABLE IF NOT EXISTS schema_meta(key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS observations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER, run_ts TEXT,
  fingerprint TEXT, company TEXT, source TEXT, kind TEXT, title TEXT,
  detail TEXT, evidence_url TEXT, base_severity REAL, observed_at TEXT,
  score REAL, severity TEXT, score_reasons TEXT
);

CREATE TABLE IF NOT EXISTS findings(
  fingerprint TEXT PRIMARY KEY,
  company TEXT, source TEXT, kind TEXT, title TEXT, detail TEXT,
  evidence_url TEXT, base_severity REAL, observed_at TEXT,
  first_seen TEXT, last_seen TEXT,
  score REAL, severity TEXT, score_reasons TEXT,
  triage TEXT DEFAULT 'new', triage_note TEXT DEFAULT '', triage_at TEXT,
  updated_at TEXT
);
CREATE INDEX IF NOT EXISTS ix_find_sev   ON findings(severity);
CREATE INDEX IF NOT EXISTS ix_find_co    ON findings(company);
CREATE INDEX IF NOT EXISTS ix_find_src   ON findings(source);
CREATE INDEX IF NOT EXISTS ix_find_tri   ON findings(triage);
CREATE INDEX IF NOT EXISTS ix_find_score ON findings(score);

CREATE TABLE IF NOT EXISTS companies(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL,
  domains TEXT, cidrs TEXT, aliases TEXT, tags TEXT,
  criticality REAL DEFAULT 1.0, created_at TEXT, updated_at TEXT
);

CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT, finished_at TEXT,
  status TEXT,                       -- running | done | failed | cancelled
  trigger TEXT,                      -- manual | cli
  summary TEXT,                      -- {new, recurring, total_in_lake}
  collectors TEXT                    -- [{name, status, count, error}]
);

-- key validation results (names only; secret VALUES live in the OS keychain)
CREATE TABLE IF NOT EXISTS secrets_meta(
  name TEXT PRIMARY KEY, validated_at TEXT, ok INTEGER
);

-- observations are an append-only audit log: refuse edits/deletes so the
-- historical record can always be trusted.
CREATE TRIGGER IF NOT EXISTS observations_no_update
  BEFORE UPDATE ON observations
  BEGIN SELECT RAISE(ABORT, 'observations is append-only'); END;
CREATE TRIGGER IF NOT EXISTS observations_no_delete
  BEFORE DELETE ON observations
  BEGIN SELECT RAISE(ABORT, 'observations is append-only'); END;
"""

_FINDING_COLS = (
    "fingerprint", "company", "source", "kind", "title", "detail",
    "evidence_url", "base_severity", "observed_at", "first_seen", "last_seen",
    "score", "severity", "score_reasons", "triage", "triage_note",
    "triage_at", "updated_at",
)


class Store:
    """A connection to one securitysight SQLite database."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: a later phase shares this across the Flask
        # thread and the run worker; WAL + a single-run lock keep writes safe.
        self.conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(_DDL)
        self.conn.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO NOTHING",
            (str(SCHEMA_VERSION),),
        )
        self.conn.commit()

    def commit(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # ----------------------------------------------------------- findings
    @staticmethod
    def _record(row: sqlite3.Row) -> dict:
        """Row -> the dict shape scoring/assets/dashboard expect (was a state.json value)."""
        return {
            "fingerprint": row["fingerprint"],
            "company": row["company"], "source": row["source"],
            "kind": row["kind"], "title": row["title"],
            "detail": json.loads(row["detail"] or "{}"),
            "evidence_url": row["evidence_url"],
            "base_severity": row["base_severity"],
            "observed_at": row["observed_at"],
            "first_seen": row["first_seen"], "last_seen": row["last_seen"],
            "score": row["score"], "severity": row["severity"],
            "score_reasons": json.loads(row["score_reasons"] or "[]"),
            "triage": row["triage"], "triage_note": row["triage_note"],
            "triage_at": row["triage_at"],
        }

    @staticmethod
    def _params(rec: dict) -> dict:
        return {
            "fingerprint": rec["fingerprint"],
            "company": rec.get("company"), "source": rec.get("source"),
            "kind": rec.get("kind"), "title": rec.get("title"),
            "detail": json.dumps(rec.get("detail") or {}),
            "evidence_url": rec.get("evidence_url"),
            "base_severity": rec.get("base_severity", 0),
            "observed_at": rec.get("observed_at"),
            "first_seen": rec.get("first_seen"), "last_seen": rec.get("last_seen"),
            "score": rec.get("score", 0), "severity": rec.get("severity"),
            "score_reasons": json.dumps(rec.get("score_reasons") or []),
            "triage": rec.get("triage", "new"),
            "triage_note": rec.get("triage_note", ""),
            "triage_at": rec.get("triage_at"),
            "updated_at": utcnow_iso(),
        }

    def load_state(self) -> dict[str, dict]:
        """All current findings as {fingerprint: record} (replaces state.json load)."""
        return {r["fingerprint"]: self._record(r)
                for r in self.conn.execute("SELECT * FROM findings")}

    def upsert_finding(self, rec: dict) -> None:
        cols = ", ".join(_FINDING_COLS)
        placeholders = ", ".join(f":{c}" for c in _FINDING_COLS)
        updates = ", ".join(f"{c}=excluded.{c}" for c in _FINDING_COLS
                            if c != "fingerprint")
        self.conn.execute(
            f"INSERT INTO findings ({cols}) VALUES ({placeholders}) "
            f"ON CONFLICT(fingerprint) DO UPDATE SET {updates}",
            self._params(rec),
        )

    def upsert_findings(self, recs: Iterable[dict]) -> None:
        for rec in recs:
            self.upsert_finding(rec)

    def insert_observation(self, run_id: int, run_ts: str, rec: dict) -> None:
        self.conn.execute(
            "INSERT INTO observations(run_id, run_ts, fingerprint, company, source, "
            "kind, title, detail, evidence_url, base_severity, observed_at, score, "
            "severity, score_reasons) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (run_id, run_ts, rec["fingerprint"], rec.get("company"),
             rec.get("source"), rec.get("kind"), rec.get("title"),
             json.dumps(rec.get("detail") or {}), rec.get("evidence_url"),
             rec.get("base_severity", 0), rec.get("observed_at"),
             rec.get("score", 0), rec.get("severity"),
             json.dumps(rec.get("score_reasons") or [])),
        )

    def next_run_id(self) -> int:
        row = self.conn.execute(
            "SELECT COALESCE(MAX(run_id), 0) + 1 AS n FROM observations").fetchone()
        return row["n"]

    # ----------------------------------------------------------- companies
    def count_companies(self) -> int:
        return self.conn.execute("SELECT COUNT(*) AS c FROM companies").fetchone()["c"]

    def get_companies(self) -> list[Company]:
        out = []
        for r in self.conn.execute("SELECT * FROM companies ORDER BY id"):
            out.append(Company.from_dict({
                "name": r["name"],
                "domains": json.loads(r["domains"] or "[]"),
                "cidrs": json.loads(r["cidrs"] or "[]"),
                "aliases": json.loads(r["aliases"] or "[]"),
                "tags": json.loads(r["tags"] or "[]"),
                "criticality": r["criticality"],
            }))
        return out

    def replace_companies(self, companies: Iterable[Company]) -> None:
        now = utcnow_iso()
        self.conn.execute("DELETE FROM companies")
        for c in companies:
            self.conn.execute(
                "INSERT INTO companies(name, domains, cidrs, aliases, tags, "
                "criticality, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                (c.name, json.dumps(c.domains), json.dumps(c.cidrs),
                 json.dumps(c.aliases), json.dumps(c.tags), c.criticality, now, now),
            )
        self.conn.commit()

    # ----------------------------------------------------------- settings
    def get_settings(self) -> dict:
        return {r["key"]: json.loads(r["value"])
                for r in self.conn.execute("SELECT key, value FROM settings")}

    def replace_settings(self, settings: dict) -> None:
        self.conn.execute("DELETE FROM settings")
        for k, v in settings.items():
            self.conn.execute("INSERT INTO settings(key, value) VALUES (?, ?)",
                              (k, json.dumps(v)))
        self.conn.commit()

    def set_setting(self, key: str, value) -> None:
        self.conn.execute(
            "INSERT INTO settings(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, json.dumps(value)))
        self.conn.commit()

    # ----------------------------------------------------------- runs
    @staticmethod
    def _run_record(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"], "started_at": row["started_at"],
            "finished_at": row["finished_at"], "status": row["status"],
            "trigger": row["trigger"],
            "summary": json.loads(row["summary"] or "{}"),
            "collectors": json.loads(row["collectors"] or "[]"),
        }

    def start_run(self, trigger: str = "manual") -> int:
        cur = self.conn.execute(
            "INSERT INTO runs(started_at, status, trigger) VALUES (?, 'running', ?)",
            (utcnow_iso(), trigger))
        self.conn.commit()
        return cur.lastrowid

    def finish_run(self, run_id: int, status: str,
                   summary: dict | None = None,
                   collectors: list | None = None) -> None:
        self.conn.execute(
            "UPDATE runs SET finished_at=?, status=?, summary=?, collectors=? WHERE id=?",
            (utcnow_iso(), status, json.dumps(summary or {}),
             json.dumps(collectors or []), run_id))
        self.conn.commit()

    def get_runs(self, limit: int = 50) -> list[dict]:
        return [self._run_record(r) for r in self.conn.execute(
            "SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,))]

    def get_run(self, run_id: int) -> dict | None:
        row = self.conn.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        return self._run_record(row) if row else None

    # ----------------------------------------------------- findings query (API)
    _SORT_COLS = {"score": "score", "last_seen": "last_seen",
                  "first_seen": "first_seen", "company": "company",
                  "title": "title", "severity": "score"}

    def query_findings(self, *, severity=None, company=None, source=None,
                       status=None, q=None, sort="score", order="desc",
                       page=1, page_size=50, exclude_errors=True) -> dict:
        """Server-side filtered/sorted/paginated query -> {items,total,page,page_size}."""
        where, params = ["1=1"], []
        if exclude_errors:
            where.append("kind != 'collector_error'")
        if severity:
            sevs = severity if isinstance(severity, (list, tuple)) \
                else [s for s in str(severity).split(",") if s]
            if sevs:
                where.append("severity IN (%s)" % ",".join("?" * len(sevs)))
                params += list(sevs)
        if company:
            where.append("company = ?"); params.append(company)
        if source:
            where.append("source = ?"); params.append(source)
        if status and status != "all":
            if status == "open":
                where.append("triage = 'new'")
            else:
                where.append("triage = ?"); params.append(status)
        if q:
            where.append("(company LIKE ? OR title LIKE ? OR source LIKE ? OR detail LIKE ?)")
            params += [f"%{q}%"] * 4
        wsql = " AND ".join(where)

        total = self.conn.execute(
            f"SELECT COUNT(*) AS c FROM findings WHERE {wsql}", params).fetchone()["c"]
        col = self._SORT_COLS.get(sort, "score")
        odir = "ASC" if str(order).lower() == "asc" else "DESC"
        page = max(1, int(page))
        page_size = max(1, min(int(page_size), 500))
        rows = self.conn.execute(
            f"SELECT * FROM findings WHERE {wsql} ORDER BY {col} {odir}, score DESC "
            f"LIMIT ? OFFSET ?", params + [page_size, (page - 1) * page_size])
        return {"items": [self._record(r) for r in rows], "total": total,
                "page": page, "page_size": page_size}

    def facets(self) -> dict:
        """Dropdown options + stat-tile counts for the UI, computed server-side."""
        base = "kind != 'collector_error'"
        companies = [r["company"] for r in self.conn.execute(
            f"SELECT DISTINCT company FROM findings WHERE {base} ORDER BY company")]
        sources = [r["source"] for r in self.conn.execute(
            f"SELECT DISTINCT source FROM findings WHERE {base} ORDER BY source")]

        def cnt(extra):
            return self.conn.execute(
                f"SELECT COUNT(*) AS c FROM findings WHERE {base} AND {extra}").fetchone()["c"]

        stats = {
            "critical_open": cnt("severity='critical' AND triage='new'"),
            "high_open": cnt("severity='high' AND triage='new'"),
            "medium_open": cnt("severity='medium' AND triage='new'"),
            "triaged": cnt("triage IN ('acknowledged','dismissed')"),
            "total": cnt("1=1"),
        }
        return {"companies": companies, "sources": sources, "stats": stats}

    def set_triage(self, fingerprint: str, status: str, note: str = "") -> bool:
        now = utcnow_iso()
        cur = self.conn.execute(
            "UPDATE findings SET triage=?, triage_note=?, triage_at=?, updated_at=? "
            "WHERE fingerprint=?", (status, note, now, now, fingerprint))
        self.conn.commit()
        return cur.rowcount > 0

    # ----------------------------------------------------- company CRUD (API)
    @staticmethod
    def _company_dict(row: sqlite3.Row) -> dict:
        return {"id": row["id"], "name": row["name"],
                "domains": json.loads(row["domains"] or "[]"),
                "cidrs": json.loads(row["cidrs"] or "[]"),
                "aliases": json.loads(row["aliases"] or "[]"),
                "tags": json.loads(row["tags"] or "[]"),
                "criticality": row["criticality"]}

    def list_companies(self) -> list[dict]:
        return [self._company_dict(r)
                for r in self.conn.execute("SELECT * FROM companies ORDER BY name")]

    def add_company(self, d: dict) -> int:
        now = utcnow_iso()
        cur = self.conn.execute(
            "INSERT INTO companies(name, domains, cidrs, aliases, tags, criticality, "
            "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
            (d["name"], json.dumps(d.get("domains", [])), json.dumps(d.get("cidrs", [])),
             json.dumps(d.get("aliases", [])), json.dumps(d.get("tags", [])),
             float(d.get("criticality", 1.0)), now, now))
        self.conn.commit()
        return cur.lastrowid

    def update_company(self, cid: int, d: dict) -> bool:
        cur = self.conn.execute(
            "UPDATE companies SET name=?, domains=?, cidrs=?, aliases=?, tags=?, "
            "criticality=?, updated_at=? WHERE id=?",
            (d["name"], json.dumps(d.get("domains", [])), json.dumps(d.get("cidrs", [])),
             json.dumps(d.get("aliases", [])), json.dumps(d.get("tags", [])),
             float(d.get("criticality", 1.0)), utcnow_iso(), cid))
        self.conn.commit()
        return cur.rowcount > 0

    def delete_company(self, cid: int) -> bool:
        cur = self.conn.execute("DELETE FROM companies WHERE id=?", (cid,))
        self.conn.commit()
        return cur.rowcount > 0

    # ----------------------------------------------------- key validation meta
    def set_key_validation(self, name: str, ok: bool) -> None:
        self.conn.execute(
            "INSERT INTO secrets_meta(name, validated_at, ok) VALUES (?, ?, ?) "
            "ON CONFLICT(name) DO UPDATE SET validated_at=excluded.validated_at, "
            "ok=excluded.ok", (name, utcnow_iso(), 1 if ok else 0))
        self.conn.commit()

    def get_key_validations(self) -> dict:
        return {r["name"]: {"validated_at": r["validated_at"], "ok": bool(r["ok"])}
                for r in self.conn.execute("SELECT * FROM secrets_meta")}


def db_path(data_root: str | Path = "data") -> Path:
    """Canonical DB location inside a data root (so reset_lake can drop the dir)."""
    return Path(data_root) / "securitysight.db"
