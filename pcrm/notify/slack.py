"""Slack alerting via incoming webhook (SLACK_WEBHOOK_URL).

Alerts only on NEW findings at or above a severity threshold, so the channel
stays signal. Each alert links to the dashboard for triage. Recurring findings
never re-alert — that's the whole point of the append-only diff.
"""

from __future__ import annotations

import json
import os

from ..models import severity_label

EMOJI = {"critical": ":rotating_light:", "high": ":red_circle:",
         "medium": ":large_orange_circle:", "low": ":large_yellow_circle:",
         "info": ":white_circle:"}


def _where(f: dict) -> str:
    """One-line 'where is this' summary for an alert, from the enriched detail."""
    d = f.get("detail", {}) or {}
    loc = d.get("location", {}) or {}
    parts = []
    if loc.get("ip"):
        parts.append(loc["ip"] + (f":{loc['port']}" if loc.get("port") else ""))
    for h in (loc.get("fqdns") or [])[:3]:
        parts.append(h)
    if parts:
        return " · ".join(f"`{p}`" for p in parts)
    aa = d.get("affected_assets")
    if isinstance(aa, list):
        if aa:
            labels = []
            for a in aa[:3]:
                lab = a.get("fqdn") or a.get("ip") or "?"
                if a.get("ip") and a.get("port"):
                    lab = f"{a.get('fqdn') or a['ip']}:{a['port']}"
                labels.append(f"`{lab}`")
            return "likely on " + " · ".join(labels)
        prod = d.get("product") or ", ".join(d.get("matched_tags", [])) or "this product"
        return f"_no public host located — check inventory for {prod}_"
    return ""


def _blocks(new_findings: list[dict], dashboard_url: str) -> list[dict]:
    top = sorted(new_findings, key=lambda f: f["score"], reverse=True)
    crit = sum(1 for f in top if f["severity"] == "critical")
    high = sum(1 for f in top if f["severity"] == "high")

    blocks = [
        {"type": "header", "text": {"type": "plain_text",
         "text": "Portfolio risk — what's new today"}},
        {"type": "section", "text": {"type": "mrkdwn",
         "text": f"*{len(top)}* new findings · *{crit}* critical · *{high}* high"}},
        {"type": "divider"},
    ]
    for f in top[:10]:
        sev = f["severity"]
        reasons = "; ".join(f.get("score_reasons", [])) or "—"
        line = (f"{EMOJI.get(sev,'')} *{f['company']}* · `{f['source']}` · "
                f"score *{f['score']:g}*\n{f['title']}")
        where = _where(f)
        if where:
            line += f"\n:round_pushpin: {where}"
        line += f"\n_why:_ {reasons}"
        block = {"type": "section", "text": {"type": "mrkdwn", "text": line}}
        if f.get("evidence_url"):
            block["accessory"] = {
                "type": "button",
                "text": {"type": "plain_text", "text": "Evidence"},
                "url": f["evidence_url"],
            }
        blocks.append(block)
    if len(top) > 10:
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn",
                       "text": f"+{len(top)-10} more in the dashboard"}]})
    blocks.append({"type": "actions", "elements": [{
        "type": "button", "text": {"type": "plain_text", "text": "Open triage dashboard"},
        "url": dashboard_url, "style": "primary"}]})
    return blocks


def post_new_findings(new_findings: list[dict], *, min_severity: str = "high",
                      dashboard_url: str = "http://localhost:8000",
                      dry_run: bool = False) -> dict:
    order = ["info", "low", "medium", "high", "critical"]
    cutoff = order.index(min_severity)
    alertable = [f for f in new_findings
                 if order.index(severity_label(f["score"])) >= cutoff
                 and f["kind"] != "collector_error"]
    if not alertable:
        return {"sent": 0, "reason": "nothing at/above threshold"}

    payload = {"blocks": _blocks(alertable, dashboard_url)}
    webhook = os.environ.get("SLACK_WEBHOOK_URL")

    if dry_run or not webhook:
        # print the payload so you can see exactly what would post
        print(json.dumps(payload, indent=2))
        return {"sent": 0, "reason": "dry-run / no SLACK_WEBHOOK_URL",
                "would_send": len(alertable)}

    import requests
    r = requests.post(webhook, json=payload, timeout=15)
    r.raise_for_status()
    return {"sent": len(alertable)}
