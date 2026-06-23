"""Registry of all collectors. Import a collector here to register it."""

from __future__ import annotations

from .collectors.base import BaseCollector
from .collectors import (
    shodan,
    censys,
    crtsh,
    ransomlook,
    mallory,
    cisa_kev,
    virustotal,
    leaklookup,
    hibp,
)

# Order here is the order shown by --list and the order collectors run in.
ALL: list[type[BaseCollector]] = [
    shodan.ShodanCollector,
    censys.CensysCollector,
    crtsh.CrtShCollector,
    ransomlook.RansomLookCollector,
    mallory.MalloryBreachesCollector,
    mallory.MalloryVulnsCollector,
    cisa_kev.CisaKevCollector,
    virustotal.VirusTotalCollector,
    leaklookup.LeakLookupCollector,
    hibp.HibpCollector,
]


def select(substring: str | None = None,
           cadence: str | None = None) -> list[type[BaseCollector]]:
    """Filter collectors. `substring` matches NAME (case-insensitive); `cadence`
    matches CADENCE exactly (e.g. "daily", "weekly"). Both optional; combined."""
    out = list(ALL)
    if substring:
        s = substring.lower()
        out = [c for c in out if s in c.NAME.lower()]
    if cadence:
        cad = cadence.lower()
        out = [c for c in out if c.CADENCE.lower() == cad]
    return out


def list_table() -> str:
    """Render the table shown by `collectors.py --list`."""
    lines = ["collectors (--collectors matches any name substring; omit to run all):"]
    for cls in ALL:
        key = cls.KEY_ENV or "-"
        lines.append(
            f"  [{cls.STATUS:<4}] {cls.NAME:<16} key={key:<18} "
            f"{cls.MODE:<8}({cls.CADENCE})"
        )
    return "\n".join(lines)
