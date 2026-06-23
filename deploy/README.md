# Deployment

Two ways to run the daily collection: a **systemd timer** on a host, or
**Docker Compose**. Both keep the data lake on persistent storage and read keys
from `.env`.

---

## Option A — systemd (host install)

Assumes the repo lives at `/opt/portco-risk-monitor` and `uv` is installed.

```bash
# 1. user + location
sudo useradd --system --home /opt/portco-risk-monitor --shell /usr/sbin/nologin pcrm
sudo git clone <repo> /opt/portco-risk-monitor
cd /opt/portco-risk-monitor
sudo -u pcrm uv sync                      # or set up a .venv and edit ExecStart

# 2. config + secrets
sudo -u pcrm cp .env.example .env && sudo -u pcrm $EDITOR .env   # add keys
sudo -u pcrm $EDITOR config/companies.yaml                        # your watchlist
sudo chown -R pcrm:pcrm /opt/portco-risk-monitor
sudo chmod 600 /opt/portco-risk-monitor/.env

# 3. install the units
sudo cp deploy/systemd/portco-risk-monitor.service /etc/systemd/system/
sudo cp deploy/systemd/portco-risk-monitor.timer   /etc/systemd/system/
sudo cp deploy/systemd/portco-dashboard.service    /etc/systemd/system/   # optional
sudo systemctl daemon-reload

# 4. enable the daily timer
sudo systemctl enable --now portco-risk-monitor.timer
sudo systemctl enable --now portco-dashboard.service     # optional

# verify
systemctl list-timers portco-risk-monitor.timer
sudo systemctl start portco-risk-monitor.service         # run once now
journalctl -u portco-risk-monitor.service -f             # watch output
```

Change the schedule by editing `OnCalendar=` in the timer (`man systemd.time`).
`Persistent=true` means a missed run (box was off) fires on next boot.

The dashboard service binds `127.0.0.1` — put nginx/Caddy with auth in front
before exposing it. For more than a couple of users, swap the dev server for
gunicorn (commented `ExecStart` in `portco-dashboard.service`; add `gunicorn`
to `requirements.txt`).

---

## Option B — Docker Compose

```bash
cp .env.example .env && $EDITOR .env       # add keys
$EDITOR config/companies.yaml              # your watchlist

docker compose up -d --build               # dashboard on :8000 + 24h collector loop
docker compose run --rm collector seed     # (optional) load demo data first
docker compose run --rm collector collect  # run a pass on demand
docker compose logs -f collector           # watch scheduled runs
```

`config/` is mounted read-only and the lake lives in the `pcrm-data` named
volume, so it survives rebuilds. The `collector` service runs once on start then
sleeps `PCRM_INTERVAL_SECONDS` (default 86400).

### Wall-clock-aligned runs

The built-in loop drifts (it's "every 24h from start", not "07:00 daily"). For a
fixed time, drop the `collector` service and trigger the oneshot from outside:

Host cron:
```cron
0 7 * * *  cd /path/to/portco-risk-monitor && docker compose run --rm collector collect
```

Kubernetes CronJob (sketch):
```yaml
apiVersion: batch/v1
kind: CronJob
metadata: { name: portco-risk-monitor }
spec:
  schedule: "0 7 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
            - name: collector
              image: portco-risk-monitor:latest
              args: ["collect"]
              envFrom: [{ secretRef: { name: portco-keys } }]
              volumeMounts: [{ name: data, mountPath: /app/data }]
          volumes:
            - name: data
              persistentVolumeClaim: { claimName: portco-data }
```

---

## Option C — GitHub Actions (no server at all)

Two scheduled workflows share one reusable engine:

- `.github/workflows/daily.yml` — daily collectors, 07:00 UTC
- `.github/workflows/weekly.yml` — weekly collectors (Leak-Lookup), Mondays 08:00 UTC
- `.github/workflows/risk-monitor.yml` — the engine both call (`workflow_call`)

> **The lake will contain findings about real companies.** The default setup
> commits it to a branch, and on a **public repo that branch is world-readable**
> (workflow artifacts are public too). `jmzf2017/securitysight` is public, so do
> **not** run the scheduled workflow with real targets there as-is. Either run
> your monitoring instance from a **private** repo, or switch lake persistence to
> private external storage (see the S3 note below) so nothing sensitive lands in
> a public branch. Publishing the *code* publicly is fine; publishing a *lake of
> real findings* is not.

Setup:

1. **Secrets** (Settings → Secrets and variables → Actions). Add the keys you
   have; missing ones just skip their collector:
   `SHODAN_API_KEY`, `CENSYS_PAT`, `MALLORY_API_KEY`, `HIBP_API_KEY`,
   `VT_API_KEY`, `LEAKLOOKUP_API_KEY`, `SLACK_WEBHOOK_URL`.
2. **Workflow permissions**: Settings → Actions → General → Workflow permissions →
   "Read and write permissions" (lets the run commit the lake branch). The
   workflow also declares `permissions: contents: write`.
3. **Watchlist**: edit `config/companies.yaml` and push to `main`.
4. Enable the workflows in the Actions tab. Trigger a first run manually via
   "Run workflow" (tick *dry run* to preview the Slack post without sending).

How it works:

- The lake is persisted on a dedicated branch (`risk-lake`, auto-created on first
  run). Daily and weekly **share** it, so a weekly credential leak still
  correlates against the exposed services a daily run found.
- Each run posts only newly-seen findings to Slack and writes a top-10 table to
  the **job summary** (visible on the run page).
- Cron is **UTC** and GitHub may delay scheduled runs under load — treat the
  times as approximate. `concurrency` prevents daily and weekly from pushing the
  lake branch simultaneously.

Tuning:

- Change times by editing `cron:` in `daily.yml` / `weekly.yml` (UTC).
- Change the lake branch via the `lake_branch` input on the reusable workflow.
- Prefer external storage? Replace the "Restore lake" / "Persist lake" steps with
  an S3 sync (`aws s3 sync s3://bucket/lake ./data` before, and back after) and
  drop `contents: write`. That keeps the lake out of git entirely.

---

## Notes

- Secrets only ever come from `.env` / a secrets manager — never committed.
- Collectors without their key are skipped, so a partial `.env` is fine.
- HIBP's `breacheddomain` lookups only work for domains verified on your HIBP
  account; set `HIBP_REQUEST_DELAY` to match your subscription's rate limit.
