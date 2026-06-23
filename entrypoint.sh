#!/usr/bin/env bash
# Container entrypoint. First arg selects the mode; the rest pass through.
set -euo pipefail

cmd="${1:-collect}"
shift || true

case "$cmd" in
  collect)            # one collection run, then exit (for cron / CronJob / oneshot)
    exec python collectors.py "$@" ;;
  dashboard)          # long-running triage dashboard
    exec python dashboard.py ;;
  loop)               # run now, then every PCRM_INTERVAL_SECONDS (default 24h)
    interval="${PCRM_INTERVAL_SECONDS:-86400}"
    while true; do
      python collectors.py "$@" || echo "[loop] run failed; retrying next cycle" >&2
      echo "[loop] sleeping ${interval}s until next run" >&2
      sleep "$interval"
    done ;;
  seed)               # load demo data into the mounted volume
    exec python seed_demo.py ;;
  *)                  # anything else: run it verbatim
    exec "$cmd" "$@" ;;
esac
