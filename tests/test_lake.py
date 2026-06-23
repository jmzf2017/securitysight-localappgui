"""Tests for lake reset (pcrm.lake.reset_lake). Uses tempfile (no fixtures)."""

import shutil
import tempfile
from pathlib import Path

from pcrm.lake import reset_lake


def test_reset_archive_moves_lake_aside():
    base = tempfile.mkdtemp()
    try:
        data = Path(base) / "data"
        (data / "observations").mkdir(parents=True)
        (data / "state.json").write_text("{}")
        res = reset_lake(str(data))
        assert res["action"] == "archived"
        assert not data.exists()
        baks = list(Path(base).glob("data.bak.*"))
        assert len(baks) == 1 and (baks[0] / "state.json").exists()
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_reset_purge_deletes_lake():
    base = tempfile.mkdtemp()
    try:
        data = Path(base) / "data"
        data.mkdir()
        (data / "state.json").write_text("{}")
        res = reset_lake(str(data), purge=True)
        assert res["action"] == "purged"
        assert not data.exists()
        assert not list(Path(base).glob("data.bak.*"))
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_reset_no_lake_is_noop():
    base = tempfile.mkdtemp()
    try:
        res = reset_lake(str(Path(base) / "nope"))
        assert res["action"] == "none"
    finally:
        shutil.rmtree(base, ignore_errors=True)
