<!-- Thanks for contributing to securitysight! -->

## What does this change?

<!-- A short description. Link any related issue (e.g. Closes #12). -->

## If this adds or changes a collector / data source

- Source: <!-- e.g. Shodan, crt.sh -->
- Auth model: <!-- API key? domain verification? none? -->
- Rate limits: <!-- and how the collector respects them -->

## Checklist

- [ ] **Passive only** — no active scanning, probing, brute-forcing, or exploitation of any target.
- [ ] **No new secrets or unnecessary PII persisted** — counts and masked samples only (see the HIBP / Leak-Lookup pattern).
- [ ] **Fails soft** — a collector or API error can't sink a run.
- [ ] Reuses an existing `Finding` `kind`, or documents a new one.
- [ ] Any scoring change records a plain-English reason in `score_reasons`.
- [ ] Tests added/updated, and `pytest` passes locally.
