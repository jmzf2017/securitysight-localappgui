"""RansomLook — public ransomware leak-site tracker. No API key.

When a ransomware crew posts a victim to their leak site, RansomLook indexes it.
A portfolio company appearing here is about as high-signal as it gets: it means
they're likely already breached. We match recent victim postings against each
company's name/aliases/domains.

RansomLook exposes a public JSON API; the recent-entries endpoint is used here.
If the endpoint shape changes, only _fetch_recent() needs adjusting.
"""

from __future__ import annotations

from ..models import Company, Finding
from .base import BaseCollector

BASE = "https://www.ransomlook.io/api"


class RansomLookCollector(BaseCollector):
    NAME = "RansomLook"
    KEY_ENV = ""
    CADENCE = "daily"
    STATUS = "live"

    def _fetch_recent(self) -> list[dict]:
        http = self._http()
        # /recent returns the latest victim postings across all groups.
        r = http.get(f"{BASE}/recent", timeout=self.TIMEOUT)
        r.raise_for_status()
        data = r.json()
        # Normalize: API returns a list of {post_title, group_name, discovered, ...}
        return data if isinstance(data, list) else data.get("posts", [])

    def collect(self, companies: list[Company]) -> list[Finding]:
        try:
            recent = self._fetch_recent()
        except Exception as e:  # noqa: BLE001
            return [Finding(
                company="(feed)", source=self.NAME, kind="collector_error",
                title="RansomLook feed fetch failed",
                detail={"_id": "rl:err", "error": str(e)}, base_severity=0,
            )]

        findings: list[Finding] = []
        for co in companies:
            needles = [t.lower() for t in co.search_terms()]
            for post in recent:
                title = (post.get("post_title") or post.get("title") or "").lower()
                if not title:
                    continue
                if any(n in title for n in needles):
                    group = post.get("group_name") or post.get("group") or "unknown"
                    when = post.get("discovered") or post.get("date") or ""
                    findings.append(Finding(
                        company=co.name,
                        source=self.NAME,
                        kind="ransomware_mention",
                        title=f"Listed on {group} leak site",
                        detail={
                            "_id": f"{co.name}:{group}:{post.get('post_title','')}",
                            "group": group,
                            "post_title": post.get("post_title") or post.get("title"),
                            "discovered": when,
                        },
                        evidence_url=post.get("link") or "https://www.ransomlook.io/",
                        base_severity=95,  # near-certain active compromise
                    ))
        return findings
