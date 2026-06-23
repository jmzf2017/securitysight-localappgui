#!/usr/bin/env python3
"""portco-risk-monitor CLI.

Usage:
  uv run collectors.py --list                 show the collector registry
  uv run collectors.py                         run all ready collectors
  uv run collectors.py --collectors shodan     run collectors matching a substring
  uv run collectors.py --dry-run               run, print the Slack payload, don't post
  uv run collectors.py --no-alert              run without alerting

Then serve the triage dashboard:
  uv run dashboard.py
"""

from __future__ import annotations

import argparse
import sys

from pcrm import registry
from pcrm.pipeline import run


def main() -> int:
    p = argparse.ArgumentParser(
        prog="collectors.py",
        description="Passive portfolio attack-surface & threat monitor.")
    p.add_argument("--list", action="store_true",
                   help="list collectors and exit")
    p.add_argument("--collectors", metavar="SUBSTR", default=None,
                   help="only run collectors whose name contains SUBSTR")
    p.add_argument("--cadence", choices=["daily", "weekly"], default=None,
                   help="only run collectors with this cadence")
    p.add_argument("--no-alert", action="store_true",
                   help="don't send Slack alerts")
    p.add_argument("--dry-run", action="store_true",
                   help="print the Slack payload instead of posting")
    p.add_argument("--companies", default="config/companies.yaml")
    p.add_argument("--settings", default="config/settings.yaml")
    p.add_argument("--data", default="data")
    p.add_argument("--import-config", action="store_true",
                   help="(re)import the YAML watchlist/settings into the SQLite store and exit")
    p.add_argument("--export-config", action="store_true",
                   help="write the SQLite watchlist/settings back out to YAML and exit")
    p.add_argument("--reset", action="store_true",
                   help="clear the data lake and exit (archives to data.bak.<ts>)")
    p.add_argument("--purge", action="store_true",
                   help="with --reset: permanently delete instead of archiving")
    p.add_argument("--yes", action="store_true",
                   help="skip confirmation prompts (for scripts)")
    args = p.parse_args()

    if args.list:
        print(registry.list_table())
        return 0

    if args.import_config or args.export_config:
        from pcrm.store import Store, db_path
        from pcrm.config import import_config_yaml, export_config_yaml
        store = Store(db_path(args.data))
        if args.import_config:
            import_config_yaml(store, args.companies, args.settings)
            print(f"imported {store.count_companies()} companies + settings into "
                  f"{db_path(args.data)}", file=sys.stderr)
        else:
            export_config_yaml(store, args.companies, args.settings)
            print(f"exported watchlist/settings to {args.companies} / {args.settings}",
                  file=sys.stderr)
        return 0

    if args.reset:
        from pcrm.lake import reset_lake
        verb = "PERMANENTLY DELETE" if args.purge else "archive"
        if not args.yes:
            print(f"This will {verb} the lake at '{args.data}' and clear ALL "
                  f"triage history (acknowledge/dismiss).", file=sys.stderr)
            resp = input("Continue? [y/N] ").strip().lower()
            if resp not in ("y", "yes"):
                print("Aborted — nothing changed.", file=sys.stderr)
                return 1
        result = reset_lake(args.data, purge=args.purge)
        if result["action"] == "none":
            print(f"Nothing to reset: {result['detail']}", file=sys.stderr)
        elif result["action"] == "archived":
            print(f"Lake archived to {result['detail']} — next run starts fresh.",
                  file=sys.stderr)
        else:
            print(f"Lake purged ({result['detail']}) — next run starts fresh.",
                  file=sys.stderr)
        return 0

    print("running collectors…", file=sys.stderr)
    summary = run(
        collector_filter=args.collectors,
        cadence=args.cadence,
        companies_path=args.companies,
        settings_path=args.settings,
        data_root=args.data,
        alert=not args.no_alert,
        dry_run=args.dry_run,
    )
    print(
        f"\ndone: {summary['new']} new, {summary['recurring']} recurring, "
        f"{summary['total_in_lake']} total in lake. "
        f"alert: {summary['alert']}",
        file=sys.stderr,
    )
    if summary["skipped"]:
        print("skipped: " + ", ".join(f"{n} ({w})" for n, w in summary["skipped"]),
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
