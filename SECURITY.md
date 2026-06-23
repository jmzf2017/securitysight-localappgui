# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for a security problem in securitysight —
for example, a way the tool could be abused, a data-handling flaw, or a way it
might leak sensitive findings.

Report it privately via this repository's **Security → Report a vulnerability**
tab (GitHub private vulnerability reporting), or to the maintainer directly.
We'll acknowledge the report and work on a fix before any public disclosure.

## Running it safely

securitysight collects and stores findings about whatever is on its watchlist.
Treat that data — and the configuration that points at real assets — as
sensitive.

- **Don't run scheduled collection from a public repository against real
  companies.** The default setup commits the findings lake to a branch, which is
  world-readable on a public repo (workflow artifacts are too). Run your
  instance from a **private** repo, or switch the lake to private storage (see
  [`deploy/README.md`](deploy/README.md)).
- **Keep API keys in secrets**, never in committed files. Collectors without
  their key are simply skipped.
- **Monitor only what you're authorized to monitor** — your own organization,
  portfolio companies, or vendors under agreement.

## Scope

securitysight is **passive**: it reads public feeds and third-party indexes and
never touches the monitored assets' infrastructure. Contributions that add
active scanning, probing, or exploitation are out of scope and won't be merged.
