# PLAN — securitysight desktop app (v0.4.0)

Turn securitysight from a CLI/cron tool with a read-only Flask dashboard into a
**local, single-user, distributable desktop application** that an analyst can
operate end-to-end — manage API keys, edit the watchlist, tune the simple
settings, trigger runs, and triage findings — without touching a terminal.

This document is the agreed design and build sequence. It is the output of a
decision interview; §1 records every decision and why, so the rationale isn't
lost.

---

## 1. Decisions (locked) and rationale

| # | Decision | Choice | Why |
|---|---|---|---|
| Topology | Who runs it, where | **Local desktop, single analyst** | No multi-user/auth/RBAC/tenant isolation needed; OS keychain is viable; "concurrency" is just guarding against a double-run. |
| v1 scope | What the GUI unlocks | **Operate without the CLI · Richer triage/analysis · Distributable** | (Not multi-user workflow.) Drives a settings/keys/runs surface + server-side query + packaging. |
| Shell | How the app is built | **Desktop shell wrapping the web UI** | Reuses the polished web dashboard (sunk asset); best "installed app" feel. |
| Platforms | OS targets | **macOS + Windows** | Covers analysts; Linux deferred. |
| Shell tech | Concrete toolchain | **pywebview + PyInstaller** | All-Python, one process, system webview (WKWebView / Edge WebView2), small bundles, no second language. |
| UI↔Python | How JS calls Python | **Flask HTTP server in a background thread** | Reuses existing `/api` routes + fetch UI verbatim; stays browser-debuggable. |
| Data layer | Where findings live | **Full SQLite (observations + index)** | Server-side filter/paginate/sort + history at volume. Audit trail preserved via an insert-only table (§4) + JSONL export. |
| Run model | How a run executes | **Background thread + single-run lock** | Single user → no real write contention; UI polls a status endpoint for live progress/errors. |
| Secrets | Where keys live | **OS keychain via `keyring`** | macOS Keychain / Windows Credential Manager; injected into the run env at runtime so collectors are unchanged; no plaintext on disk. |
| Config store | Watchlist + settings | **SQLite, with YAML import/export** | Consistent with the SQLite direction; forms read/write the DB; YAML kept for backup/portability. |
| Config UX | How config is edited | **Structured forms** (assumed) | Raw-YAML editing contradicts the non-technical goal. |
| Scheduling | Unattended runs | **Manual only (v1)** | Drops the background-agent/launchd/Task Scheduler install from v1. |
| Headless | Fate of the CLI | **Keep a headless runner on the SQLite core** | App + CLI share one core; preserves scriptability; unlocks future scheduling cheaply. |
| Scoring config | Tunable weights | **Expose existing knobs only** | `alert_min_severity` + per-company `criticality`; correlation weights stay fixed (trustworthy/consistent). |
| Signing | Distribution trust | **Unsigned (v1, internal/beta)** | No cert cost now; **add signing before any external release** (see Risks). |
| Updates | How users upgrade | **In-app update notice → manual download** | App checks latest version, links to download; little infra. |
| First run | Onboarding | **Key wizard (live-validated) · optional demo seed · watchlist builder** | (Not "import existing CLI setup" — handled by a separate migration utility, §8.) |

**Assumed defaults (flag if wrong):** data + DB stored in the OS per-user app
dir via `platformdirs` (a packaged app cannot write beside its bundle); internal
package name stays `pcrm`; demo seed reuses `seed_demo.py`.

---

## 2. What is preserved vs changed

**Preserved (the good bones — do not rewrite):**
- `Finding` / `Company` model + fingerprinting (`pcrm/models.py`).
- Collector plugin contract + registry (`pcrm/collectors/base.py`, `pcrm/registry.py`).
- Scoring & asset correlation logic (`pcrm/scoring.py`, `pcrm/assets.py`).
- Pipeline orchestration `collect → ingest → enrich → score → alert` (`pcrm/pipeline.py`).
- Dashboard visual design (`templates/index.html` styling).

**Changed / added:** persistence (JSONL+state.json → SQLite), config source
(YAML → SQLite), secret handling (`.env` → keychain), run execution (blocking →
threaded+locked), web layer (whole-lake-to-page → REST API + multi-view UI), and
a pywebview shell + packaging.

---

## 3. Target architecture

```
            ┌─────────────────────────── pywebview window ───────────────────────────┐
            │  native webview (WKWebView / WebView2)  →  http://127.0.0.1:<ephemeral>  │
            └───────────────────────────────────┬──────────────────────────────────--┘
                                                 │ fetch() JSON
                                   ┌─────────────▼──────────────┐
                                   │  Flask app (factory)        │  ← thread, in-process
                                   │  REST API (§5)              │
                                   └───┬───────────┬────────────-┘
                          ┌────────────┘           └─────────────┐
                 ┌────────▼────────┐                    ┌─────────▼─────────┐
                 │ RunManager      │  one run at a time  │ store.py (SQLite) │
                 │ (worker thread, │────writes──────────▶│ WAL; observations │
                 │  status object) │                    │ findings/companies│
                 └───┬─────────────┘                    │ settings/runs     │
                     │ calls                             └─────────▲─────────┘
              ┌──────▼───────────────────────────┐                │ read/write
              │ pipeline.run() (unchanged shape)  │                │
              │  collect→ingest→enrich→score→alert│────────────────┘
              └──────┬────────────────────────────┘
                     │ os.environ (injected for run duration)
              ┌──────▼──────┐        ┌──────────────┐
              │ collectors  │        │ secrets.py   │  ← keyring (OS keychain)
              └─────────────┘        └──────────────┘

  main.py: single-instance guard · platformdirs data dir · start Flask thread · open window
  collectors.py (CLI): same core, headless — preserved for scripting
```

---

## 4. SQLite schema (sketch)

WAL mode on. `detail` / list columns stored as JSON text.

```sql
schema_meta(key TEXT PRIMARY KEY, value TEXT);     -- {"schema_version": "1"}

-- insert-only audit trail (replaces observations/*.jsonl).
-- UPDATE/DELETE blocked by triggers so the "diff any two days" property holds.
observations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id INTEGER, run_ts TEXT,
  fingerprint TEXT, company TEXT, source TEXT, kind TEXT, title TEXT,
  detail TEXT, evidence_url TEXT, base_severity REAL, observed_at TEXT,
  score REAL, severity TEXT, score_reasons TEXT
);

-- current derived state, one row per fingerprint (replaces state.json)
findings(
  fingerprint TEXT PRIMARY KEY,
  company TEXT, source TEXT, kind TEXT, title TEXT, detail TEXT,
  evidence_url TEXT, base_severity REAL,
  first_seen TEXT, last_seen TEXT,
  score REAL, severity TEXT, score_reasons TEXT,
  triage TEXT DEFAULT 'new',          -- new | acknowledged | dismissed
  triage_note TEXT DEFAULT '', triage_at TEXT,
  updated_at TEXT
);
-- indexes: severity, company, source, triage, score, last_seen

companies(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL,
  domains TEXT, cidrs TEXT, aliases TEXT, tags TEXT,
  criticality REAL DEFAULT 1.0, created_at TEXT, updated_at TEXT
);

settings(key TEXT PRIMARY KEY, value TEXT);   -- alert_min_severity, dashboard_url, …

runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT, finished_at TEXT,
  status TEXT,                         -- running | done | failed | cancelled
  trigger TEXT,                        -- manual | cli
  summary TEXT,                        -- {new, recurring, total_in_lake}
  collectors TEXT                      -- [{name, status, count, error}]
);
```

API keys live **only** in the keychain (`keyring`), never in SQLite.

---

## 5. REST API contract (localhost only)

| Method · Path | Purpose |
|---|---|
| `GET /api/findings?severity=&company=&source=&status=&q=&sort=&page=&page_size=` | Server-side filtered/sorted/paginated queue → `{items, total, page, page_size}` |
| `POST /api/triage` | `{fingerprint, status, note}` → set triage |
| `GET/POST /api/companies`, `PUT/DELETE /api/companies/<id>` | Watchlist CRUD (validated) |
| `GET/PUT /api/settings` | Read/update the simple knobs |
| `GET /api/keys` | Key **names** + set/unset + last-validated — **never values** |
| `PUT /api/keys/<name>` · `DELETE /api/keys/<name>` | Store / remove a key in the keychain |
| `POST /api/keys/<name>/validate` | Live provider probe → `{ok, detail}` |
| `POST /api/run` | `{collectors?, cadence?, no_alert?}` → `{run_id}` (409 if one is running) |
| `GET /api/run/status` | Current/last run progress + per-collector results |
| `GET /api/runs?page=` | Run history |
| `GET /api/export` · `POST /api/import` | Config ↔ YAML |
| `POST /api/seed-demo` | Load `seed_demo.py` sample data (onboarding) |
| `GET /api/version` | `{current, latest?, update_url?}` for the update notice |

UI becomes a multi-view app over these — **Triage / Watchlist / Keys /
Settings / Runs** — reusing the existing CSS; the embedded `{{ findings|tojson }}`
blob is removed in favor of `GET /api/findings`.

---

## 6. Module-level work

| File | Change |
|---|---|
| `pcrm/store.py` *(new)* | SQLite connection (WAL), schema + migrations, `observations` insert-only triggers, query helpers. |
| `pcrm/lake.py` | Re-implement `Lake` as a thin facade over `store.py` (same method names so `pipeline`/`scoring` barely change); keep `reset_lake`. |
| `pcrm/secrets.py` *(new)* | `keyring` wrapper (set/get/delete/list, never echo) + run-scoped `os.environ` injector. |
| `pcrm/runner.py` *(new)* | `RunManager`: single-run lock, worker thread, live status object, `runs` row lifecycle. |
| `pcrm/config.py` | Read companies/settings from SQLite; add YAML import/export. |
| `pcrm/collectors/base.py` | Optional `validate()` probe for live key-checking (format-only fallback). |
| `dashboard.py` → `pcrm/web.py` *(refactor)* | Flask app factory + the REST API in §5; drop whole-lake-to-page. |
| `templates/index.html` | Multi-view app; fetch via API; reuse styling. |
| `main.py` *(new)* | pywebview entry: platformdirs data dir, single-instance guard, start Flask thread, open window. |
| `collectors.py` | Keep CLI; point at the SQLite core. |
| `packaging/` *(new)* | PyInstaller specs (`.app` + Windows `.exe`), build scripts (unsigned). |
| `tests/` | Port `test_lake` to SQLite; add store/secrets/runner/API tests; keep all current tests green. |

---

## 7. Build sequence (each phase ends runnable + tests green)

**Phase 1 — SQLite core** ✅ *done*
- [x] `store.py` schema + migrations + insert-only triggers (`observations` UPDATE/DELETE blocked).
- [x] `Lake` facade over SQLite; `pipeline`/`scoring`/`assets` unchanged in behavior (in-memory-state model preserved so in-place enrichment persists).
- [x] Config read from SQLite + YAML import/export (`config.py` + `collectors.py --import-config/--export-config`); first-run auto-seeds from YAML.
- [x] `test_lake.py` still valid (reset is dir-level); added `tests/test_store.py` — **97 tests pass** (88 prior + 9 store).
- [x] CLI (`collectors.py`) works headless against SQLite (verified offline).

**Phase 2 — secrets + runs** ✅ *done*
- [x] `secrets.py`: `SecretStore` (keyring; pluggable backend), `known_secret_names()`, `injected_env()` run-scoped env, `validate_key()`.
- [x] `RunManager` (`runner.py`): threaded run, single-run lock, live status object, `runs` row lifecycle, secret injection. `runs` table + methods added to `store.py`. Pipeline emits progress via an optional `on_event` callback (behavior unchanged when absent).
- [x] Per-collector `validate()` probes on `BaseCollector` (presence/format default + `_validate_live` hook; Shodan implements a live probe as the pattern).
- [x] `tests/test_secrets.py` + `tests/test_runner.py` — **109 tests pass** (97 prior + 12). `keyring>=24` added to requirements.

**Phase 3 — API layer** ✅ *done*
- [x] Flask **app factory** (`pcrm/web.py`, `create_app`); `dashboard.py` is now a thin entry (keeps `python dashboard.py` + WSGI `dashboard:app`). Per-request `Store` via app context.
- [x] All §5 endpoints: server-side `/api/findings` (filter/sort/paginate via `store.query_findings`), `/api/triage`, companies CRUD, `/api/settings`, `/api/keys` (+validate, names-only), `/api/run` (+`/status`, 409 when busy), `/api/runs`, `/api/export`+`/api/import`, `/api/seed-demo`, `/api/version`.
- [x] `seed_demo.py` refactored into a callable `seed(data_root)` (no import side-effects).
- [x] `tests/test_api.py` — findings query/paginate, triage+filter, CRUD (+dup 409, invalid 400), settings, **keys never leak values** + validate, run lifecycle + busy-409, export/import, seed-demo. **119 tests pass.**
- Note: the KEV cache path (`cisa_kev.CACHE`) is still cwd-relative (`data/cache`), not data-root-aware — follow-up for Phase 5 packaging.

**Phase 4 — UI views** ✅ *done*
- [x] `templates/index.html` reworked into a 5-view SPA (Triage / Watchlist / API keys / Settings / Runs) over the API; existing CSS/cards reused; `<script>` wrapped in `{% raw %}`.
- [x] Triage fetches `/api/findings` (server-side filter/sort/**pagination**); stat tiles + dropdowns from a new `/api/facets`; **embedded JSON blob removed** (`index()` renders a contextless shell).
- [x] Watchlist builder (CRUD forms), Keys manager (set/validate/delete, values never shown), Settings editor, Run console (trigger + live status polling + history).
- [x] `tests/test_api.py` gains facets + contextless-render test; live UI-data-path smoke verified. **120 tests pass.**
- Note: added `/api/facets` as a small UI support endpoint (distinct companies/sources + stat counts).

**Phase 5 — shell + onboarding** ✅ *done*
- [x] `main.py`: pywebview window over the Flask app on an ephemeral port; single-instance lock (fixed loopback port); data + KEV cache in the per-user dir via `platformdirs` (`PCRM_DATA`). Helpers factored out + unit-tested.
- [x] First-run wizard (overlay in `index.html`, gated by `/api/onboarding/state`): welcome + optional demo seed → live-validated key setup → first-company builder → `/api/onboarding/complete`.
- [x] `/api/version` update-check (network-guarded behind `?check=1`, fails soft) + in-app update banner.
- [x] KEV cache (`cisa_kev.CACHE`) is now data-root-aware (resolves the Phase 3 follow-up). `platformdirs>=4`, `pywebview>=5` added.
- [x] `tests/test_main.py` + onboarding/version tests. **126 tests pass.**

**Phase 6 — packaging** ✅ *done (macOS built; Windows scripted)*
- [x] PyInstaller spec (`packaging/securitysight.spec`, frozen-aware template/static paths, hidden imports for seed_demo/keyring/pcrm) + build scripts (`build_macos.sh`, `build_windows.ps1`).
- [x] **macOS `.app` built and smoke-tested** via the new `--server` headless mode: bundled templates/SQLite/seed/keyring all resolve (seed-demo → 16 findings, index renders, v0.4.0). Unsigned.
- [x] Windows `.exe` — spec + PowerShell build script + **WebView2 bootstrap note** in `packaging/README.md`; not built here (PyInstaller can't cross-compile — build on Windows).
- [x] `packaging/README.md`: build, headless mode, WebView2, and Gatekeeper/SmartScreen bypass steps. `build/`+`dist/` git-ignored and overlay-excluded. Version bumped to **0.4.0**. `pyinstaller>=6` added (dev).
- Remaining before external release: **code signing** (Apple notarization + Windows Authenticode) and a Windows build on a Windows host.

---

## 8. One-time migration utility (separate from onboarding)

Because "import existing CLI setup" was *not* chosen for onboarding, but your
real running instance must not be stranded:

- [ ] `tools/migrate_to_sqlite.py` — read an existing `data/state.json` +
  `data/observations/*.jsonl` and `config/companies.yaml` + `settings.yaml`,
  load them into the new SQLite store (observations preserved, triage state
  preserved). Idempotent; run once against the private instance.

---

## 9. Risks / watch-items

- **Unsigned bundles** → Gatekeeper/SmartScreen warnings. Acceptable for
  internal/beta only; **add Apple notarization + Windows Authenticode before any
  external release.**
- **Live key validation** consumes quota on some providers and a few lack a cheap
  check → make validation cheap and optional per collector; format-only fallback.
- **WebView2 runtime** absent on older Windows → bundle/bootstrap the Evergreen
  installer or document the prerequisite.
- **Audit trail**: insert-only `observations` + JSONL export replace the loose
  files; the GitHub Actions "risk-lake branch" persistence is **retired** for the
  desktop app (document this).
- **Secrets hygiene**: keys live in env only for a run's duration; never log them;
  `/api/keys` returns names/status only.
- **SQLite + threads**: WAL + the single-run lock keep one writer; the Flask
  thread reads.

---

## 10. Out of scope for v1 (explicit)

Multi-user/auth/RBAC · scheduled/unattended runs · code signing · auto-update ·
fully-configurable scoring rules · Linux packaging · importing an existing CLI
setup *during onboarding* (covered by the standalone migration utility instead).
