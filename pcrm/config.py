"""Watchlist + settings.

Canonical store is SQLite (pcrm/store.py); YAML is now an import/export format,
kept so existing setups seed transparently and so config stays git/backup-able.
The YAML loaders below are still the parsers, reused by the import helpers.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from .models import Company

DEFAULT_COMPANIES = "config/companies.yaml"
DEFAULT_SETTINGS = "config/settings.yaml"


def load_companies(path: str | Path = DEFAULT_COMPANIES) -> list[Company]:
    data = yaml.safe_load(Path(path).read_text()) or {}
    return [Company.from_dict(c) for c in data.get("companies", [])]


def load_settings(path: str | Path = DEFAULT_SETTINGS) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    return yaml.safe_load(p.read_text()) or {}


# --- SQLite-backed config (the canonical path used by the pipeline/CLI) ------

def import_config_yaml(store, companies_path: str | Path = DEFAULT_COMPANIES,
                       settings_path: str | Path = DEFAULT_SETTINGS) -> None:
    """Replace the store's watchlist + settings from YAML files."""
    if Path(companies_path).exists():
        store.replace_companies(load_companies(companies_path))
    settings = load_settings(settings_path)
    if settings:
        store.replace_settings(settings)


def ensure_config_seeded(store, companies_path: str | Path = DEFAULT_COMPANIES,
                         settings_path: str | Path = DEFAULT_SETTINGS) -> None:
    """First-run bootstrap: if the store is empty, import the YAML config so an
    existing CLI setup keeps working without any manual migration step."""
    if store.count_companies() == 0 and Path(companies_path).exists():
        store.replace_companies(load_companies(companies_path))
    if not store.get_settings():
        settings = load_settings(settings_path)
        if settings:
            store.replace_settings(settings)


def export_config_yaml(store, companies_path: str | Path = DEFAULT_COMPANIES,
                       settings_path: str | Path = DEFAULT_SETTINGS) -> None:
    """Write the store's watchlist + settings back out to YAML (backup/portability)."""
    companies = [
        {"name": c.name, "domains": c.domains, "cidrs": c.cidrs,
         "aliases": c.aliases, "tags": c.tags, "criticality": c.criticality}
        for c in store.get_companies()
    ]
    Path(companies_path).write_text(
        yaml.safe_dump({"companies": companies}, sort_keys=False))
    Path(settings_path).write_text(
        yaml.safe_dump(store.get_settings(), sort_keys=False))


def export_config_strings(store) -> dict:
    """Return the store's watchlist + settings as YAML strings (for /api/export)."""
    companies = [
        {"name": c.name, "domains": c.domains, "cidrs": c.cidrs,
         "aliases": c.aliases, "tags": c.tags, "criticality": c.criticality}
        for c in store.get_companies()
    ]
    return {"companies": yaml.safe_dump({"companies": companies}, sort_keys=False),
            "settings": yaml.safe_dump(store.get_settings(), sort_keys=False)}


def import_config_strings(store, companies_yaml: str | None = None,
                          settings_yaml: str | None = None) -> None:
    """Replace the store's watchlist/settings from YAML strings (for /api/import)."""
    if companies_yaml is not None:
        data = yaml.safe_load(companies_yaml) or {}
        store.replace_companies([Company.from_dict(c)
                                 for c in data.get("companies", [])])
    if settings_yaml is not None:
        store.replace_settings(yaml.safe_load(settings_yaml) or {})
