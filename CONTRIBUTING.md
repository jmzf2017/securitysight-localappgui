# Contributing to securitysight

Thanks for your interest in improving securitysight. This is a defensive,
passive monitoring tool, and contributions are very welcome — most usefully new
collectors and scoring rules.

## Ground rules

These are the boundaries that define the project. PRs that cross them won't be
merged, no matter how useful:

1. **Passive only.** Collectors query public feeds and third-party indexes. No
   active scanning, port-knocking, probing, brute-forcing, credential testing,
   or exploitation of any target — ever.
2. **Authorized use.** The tool is for monitoring assets you own or are
   authorized to monitor. Don't add features whose main purpose is targeting
   third parties without authorization.
3. **Minimize sensitive data.** Never persist raw secrets (passwords, tokens) or
   unnecessary PII to the lake. Store counts and masked samples — see
   `pcrm/collectors/hibp.py` and `pcrm/collectors/leaklookup.py` for the
   pattern, including the redaction helpers.
4. **Fail soft.** One collector or API error must never sink a run. Catch it,
   emit a `collector_error` finding, and return what you have.

## Dev setup

```bash
git clone https://github.com/jmzf2017/securitysight
cd securitysight
uv sync                      # or: python -m venv .venv && pip install -r requirements.txt

uv run seed_demo.py          # load sample findings (no API keys needed)
uv run dashboard.py          # http://localhost:8000
uv run collectors.py --list  # see the collector registry
```

`seed_demo.py` gives you a fully populated lake offline, so you can work on
scoring and the dashboard without any keys. Delete `data/` to reset.

## Adding a collector

1. Create a module in `pcrm/collectors/`, subclass `BaseCollector`.
2. Set the class attributes: `NAME`, `KEY_ENV` (env var holding the API key, or
   `""` if none), `MODE` (`passive`), `CADENCE` (`daily`/`weekly`), `STATUS`
   (`live`/`stub`).
3. Implement `collect(self, companies) -> list[Finding]`.
4. Register the class in `pcrm/registry.py` (order = `--list` and run order).
5. If it needs a key, document it in `.env.example`.

Guidelines:

- Keep all query construction and field mapping in one place so adapting to API
  drift is a small edit.
- Reuse an existing `Finding` `kind` when the data is comparable
  (`exposed_service`, `breached_accounts`, `credential_leak`, …) so it slots
  into existing correlations; otherwise pick a clear new `kind`.
- Set `detail["_id"]` to the stable identity of the thing (host, CVE, breach) so
  the lake dedups correctly and a genuinely new item alerts.
- Respect rate limits: expose a `*_REQUEST_DELAY` env knob and honour
  `Retry-After` on 429s, as the VirusTotal and HIBP collectors do.

## Adding a scoring rule

Correlations live in `pcrm/scoring.py`, which runs over the whole lake each pass.
When you adjust a score, **always append a plain-English reason** to
`score_reasons` — the dashboard and Slack alerts surface them, and an
unexplained score is worse than no score.

## Conventions

- Python 3.10+, type hints, standard library + the existing deps where possible.
- Match the surrounding style; keep modules focused and readable.
- Tests live in `tests/` and run with `pytest` (`pip install -r requirements-dev.txt`).
  They cover the scoring correlations and credential redaction, and run in CI on
  every push and PR. Add or update tests for any change to scoring or to how
  sensitive data is handled.

## Pull requests

- Keep PRs small and focused (one collector or rule per PR is ideal).
- In the description, note the data source, its auth model, and rate limits.
- Confirm the change is passive and that no secrets/PII are newly persisted.

## Reporting a security issue

Please **do not** open a public issue for a vulnerability in this tool (for
example, a way it could be abused, or a data-handling flaw). Report it privately
via the repository's **Security → Report a vulnerability** tab on GitHub, or to
the maintainer directly. We'll acknowledge and work on a fix before any public
disclosure.

## Code of conduct

Be respectful and constructive. Assume good faith. Harassment or abuse of any
kind isn't tolerated.
