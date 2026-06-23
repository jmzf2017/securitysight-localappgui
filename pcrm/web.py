"""Flask app factory + REST API for the desktop app (Phase 3).

A single-user local server. Endpoints (all JSON unless noted):

  GET  /                       the triage dashboard (HTML)
  GET  /api/findings           server-side filtered/sorted/paginated queue
  POST /api/triage             {fingerprint, status, note}
  GET  /api/companies          list watchlist
  POST /api/companies          add a company
  PUT  /api/companies/<id>     update a company
  DELETE /api/companies/<id>   remove a company
  GET/PUT /api/settings        simple knobs (alert_min_severity, dashboard_url, …)
  GET  /api/keys               key names + set/validated state (never values)
  PUT  /api/keys/<name>        store a key in the OS keychain
  DELETE /api/keys/<name>      remove a key
  POST /api/keys/<name>/validate   verify a key (live where possible)
  POST /api/run                start a collection (409 if one is running)
  GET  /api/run/status         live status of the current/last run
  GET  /api/runs               run history
  GET  /api/export             watchlist + settings as YAML
  POST /api/import             replace watchlist/settings from YAML
  POST /api/seed-demo          load demo findings + watchlist
  GET  /api/version            current version (+ update info later)
"""

from __future__ import annotations

import os
import pathlib
import sys

from flask import Flask, g, jsonify, render_template, request

from . import __version__
from .config import export_config_strings, import_config_strings
from .runner import RunInProgress, RunManager
from .secrets import SecretStore, known_secret_names, validate_key
from .store import Store, db_path

# templates/static live next to the package in source, but at the unpack root
# (sys._MEIPASS) inside a PyInstaller bundle.
if getattr(sys, "frozen", False):
    _ROOT = pathlib.Path(sys._MEIPASS)
else:
    _ROOT = pathlib.Path(__file__).resolve().parent.parent

_RELEASES = "https://github.com/jmzf2017/securitysight/releases"


def _latest_version() -> str | None:
    """Best-effort latest release tag from GitHub; None on any failure (offline,
    rate-limited, etc.). Network only — never called unless ?check=1 is passed."""
    url = os.environ.get(
        "SSP_UPDATE_FEED",
        "https://api.github.com/repos/jmzf2017/securitysight/releases/latest")
    try:
        import requests
        r = requests.get(url, timeout=3)
        r.raise_for_status()
        return (r.json().get("tag_name") or "").lstrip("v") or None
    except Exception:  # noqa: BLE001
        return None


def _clean_company(body: dict) -> dict:
    """Validate/normalize a company payload. Raises ValueError on bad input."""
    name = (body.get("name") or "").strip()
    if not name:
        raise ValueError("name is required")

    def as_list(v):
        if v is None:
            return []
        if isinstance(v, str):
            return [s.strip() for s in v.split(",") if s.strip()]
        return list(v)

    try:
        criticality = float(body.get("criticality", 1.0))
    except (TypeError, ValueError):
        raise ValueError("criticality must be a number")
    return {"name": name, "domains": as_list(body.get("domains")),
            "cidrs": as_list(body.get("cidrs")), "aliases": as_list(body.get("aliases")),
            "tags": as_list(body.get("tags")), "criticality": criticality}


def create_app(data_root: str = "data", secret_store: SecretStore | None = None,
               run_manager: RunManager | None = None) -> Flask:
    app = Flask(__name__, template_folder=str(_ROOT / "templates"),
                static_folder=str(_ROOT / "static"))
    secrets = secret_store or SecretStore()
    runs = run_manager or RunManager(data_root=data_root, secret_store=secrets)

    def store() -> Store:
        if "store" not in g:
            g.store = Store(db_path(data_root))
        return g.store

    @app.teardown_appcontext
    def _close_store(_exc):
        s = g.pop("store", None)
        if s is not None:
            s.close()

    # ------------------------------------------------------------ dashboard
    @app.get("/")
    def index():
        # The UI is fully client-side now; it fetches everything via the API.
        return render_template("index.html")

    # ------------------------------------------------------------ findings
    @app.get("/api/facets")
    def api_facets():
        return jsonify(store().facets())

    @app.get("/api/findings")
    def api_findings():
        a = request.args
        return jsonify(store().query_findings(
            severity=a.get("severity"), company=a.get("company"),
            source=a.get("source"), status=a.get("status"), q=a.get("q"),
            sort=a.get("sort", "score"), order=a.get("order", "desc"),
            page=int(a.get("page", 1)), page_size=int(a.get("page_size", 50))))

    @app.post("/api/triage")
    def api_triage():
        d = request.get_json(force=True, silent=True) or {}
        if not d.get("fingerprint") or not d.get("status"):
            return jsonify({"error": "fingerprint and status are required"}), 400
        ok = store().set_triage(d["fingerprint"], d["status"], d.get("note", ""))
        return jsonify({"ok": ok}), (200 if ok else 404)

    # ------------------------------------------------------------ companies
    @app.get("/api/companies")
    def api_companies():
        return jsonify(store().list_companies())

    @app.post("/api/companies")
    def api_company_add():
        try:
            data = _clean_company(request.get_json(force=True, silent=True) or {})
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        try:
            cid = store().add_company(data)
        except Exception:  # noqa: BLE001 - UNIQUE(name) violation etc.
            return jsonify({"error": f"a company named {data['name']!r} already exists"}), 409
        return jsonify({"id": cid}), 201

    @app.put("/api/companies/<int:cid>")
    def api_company_update(cid):
        try:
            data = _clean_company(request.get_json(force=True, silent=True) or {})
        except ValueError as e:
            return jsonify({"error": str(e)}), 400
        return (jsonify({"ok": True}) if store().update_company(cid, data)
                else (jsonify({"error": "not found"}), 404))

    @app.delete("/api/companies/<int:cid>")
    def api_company_delete(cid):
        return (jsonify({"ok": True}) if store().delete_company(cid)
                else (jsonify({"error": "not found"}), 404))

    # ------------------------------------------------------------ settings
    @app.get("/api/settings")
    def api_settings_get():
        return jsonify(store().get_settings())

    @app.put("/api/settings")
    def api_settings_put():
        d = request.get_json(force=True, silent=True) or {}
        s = store()
        for k, v in d.items():
            s.set_setting(k, v)
        return jsonify(s.get_settings())

    # ------------------------------------------------------------ keys
    @app.get("/api/keys")
    def api_keys():
        meta = store().get_key_validations()
        out = []
        for name in known_secret_names():
            m = meta.get(name, {})
            out.append({"name": name, "set": secrets.exists(name),
                        "validated_at": m.get("validated_at"), "ok": m.get("ok")})
        return jsonify(out)

    @app.put("/api/keys/<name>")
    def api_key_set(name):
        if name not in known_secret_names():
            return jsonify({"error": f"unknown key: {name}"}), 404
        d = request.get_json(force=True, silent=True) or {}
        value = d.get("value")
        if not value:
            return jsonify({"error": "value is required"}), 400
        secrets.set(name, value)
        return jsonify({"ok": True})           # never echo the value back

    @app.delete("/api/keys/<name>")
    def api_key_delete(name):
        secrets.delete(name)
        return jsonify({"ok": True})

    @app.post("/api/keys/<name>/validate")
    def api_key_validate(name):
        d = request.get_json(force=True, silent=True) or {}
        value = d.get("value") or secrets.get(name)
        result = validate_key(name, value)
        store().set_key_validation(name, result.get("ok", False))
        return jsonify(result)

    # ------------------------------------------------------------ runs
    @app.post("/api/run")
    def api_run():
        d = request.get_json(force=True, silent=True) or {}
        try:
            run_id = runs.start(collector_filter=d.get("collectors"),
                                cadence=d.get("cadence"),
                                alert=not d.get("no_alert", False))
        except RunInProgress as e:
            return jsonify({"error": str(e)}), 409
        return jsonify({"run_id": run_id}), 202

    @app.get("/api/run/status")
    def api_run_status():
        return jsonify(runs.status())

    @app.get("/api/runs")
    def api_runs():
        return jsonify(store().get_runs(limit=int(request.args.get("limit", 50))))

    # ------------------------------------------------------------ config io
    @app.get("/api/export")
    def api_export():
        return jsonify(export_config_strings(store()))

    @app.post("/api/import")
    def api_import():
        d = request.get_json(force=True, silent=True) or {}
        import_config_strings(store(), d.get("companies"), d.get("settings"))
        return jsonify({"ok": True, "companies": store().count_companies()})

    # ------------------------------------------------------------ misc
    @app.post("/api/seed-demo")
    def api_seed_demo():
        from seed_demo import seed
        return jsonify({"ok": True, **seed(data_root)})

    @app.get("/api/version")
    def api_version():
        # ?check=1 opts into the network call; default stays offline/instant.
        latest = _latest_version() if request.args.get("check") else None
        return jsonify({"current": __version__, "latest": latest,
                        "update_url": _RELEASES})

    # ------------------------------------------------------------ onboarding
    @app.get("/api/onboarding/state")
    def api_onboarding_state():
        s = store()
        done = bool(s.get_settings().get("onboarded"))
        any_key = any(secrets.exists(n) for n in known_secret_names())
        companies = s.count_companies()
        return jsonify({"needed": (not done) and companies == 0 and not any_key,
                        "companies": companies, "any_key": any_key})

    @app.post("/api/onboarding/complete")
    def api_onboarding_complete():
        store().set_setting("onboarded", True)
        return jsonify({"ok": True})

    return app
