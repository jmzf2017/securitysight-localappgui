"""Tests for `update_repos.sh` — the `--dry-run` mode and the invariant guards
(A–D) that make the path-swap / inverted-exclude bug class impossible to commit
silently.

Each test builds a throwaway "world" in a tempdir: two bare git repos standing
in for the public/private remotes, two clones of them, and a source build whose
`update_repos.sh` is a copy of the real script (optionally text-transformed to
simulate a buggy exclude flag). This mirrors how the offline sync was validated
during development — no network, local throwaway remotes only.
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "update_repos.sh"

if shutil.which("git") is None or shutil.which("rsync") is None:
    pytest.skip("git and rsync are required for update_repos.sh tests",
                allow_module_level=True)

_GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.test",
    "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.test",
    "GIT_TERMINAL_PROMPT": "0",
}

DEMO_WATCHLIST = "companies:\n  - name: Demo\n    domains: [demo.example]\n"
REAL_WATCHLIST = "companies:\n  - name: Globex\n    domains: [globex.io]\n"


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=str(cwd), check=True,
                   env=_GIT_ENV, capture_output=True)


class World:
    def __init__(self, base: Path):
        self.base = base
        self.src = base / "src"          # the build (script ROOT)
        self.pub = base / "pub"          # public clone
        self.priv = base / "priv"        # private clone
        self.script = self.src / "update_repos.sh"


def build_world(base: Path, *, real_watchlist=False, script_replace=None,
                swap_paths=False) -> World:
    w = World(base)

    # bare "remotes" — note the private one carries the `private` discriminator.
    pub_bare = base / "securitysight.git"
    priv_bare = base / "securitysight-private.git"
    _git(base, "init", "-q", "--bare", str(pub_bare))
    _git(base, "init", "-q", "--bare", str(priv_bare))

    # source build with demo config
    (w.src / "pcrm").mkdir(parents=True)
    (w.src / "config").mkdir(parents=True)
    script_text = SCRIPT.read_text()
    if script_replace:
        old, new = script_replace
        assert old in script_text, f"transform target not found: {old!r}"
        script_text = script_text.replace(old, new)
    w.script.write_text(script_text)
    w.script.chmod(0o755)
    (w.src / "pcrm" / "__init__.py").write_text('__version__ = "0.3.1"\n')
    (w.src / "app.py").write_text("print('app')\n")
    (w.src / "config" / "companies.yaml").write_text(
        REAL_WATCHLIST if real_watchlist else DEMO_WATCHLIST)
    (w.src / "config" / "settings.yaml").write_text("alert_min_severity: high\n")
    (w.src / "context.md").write_text("Target org: Globex (private handoff)\n")

    # clones, each with an initial commit so HEAD exists
    _git(base, "clone", "-q", str(pub_bare), str(w.pub))
    (w.pub / "placeholder.txt").write_text("old\n")
    _git(w.pub, "add", "-A"); _git(w.pub, "commit", "-qm", "init")

    _git(base, "clone", "-q", str(priv_bare), str(w.priv))
    (w.priv / "config").mkdir()
    # the private clone keeps its OWN real watchlist
    (w.priv / "config" / "companies.yaml").write_text(REAL_WATCHLIST)
    (w.priv / "context.md").write_text("Target org: Globex (private handoff)\n")
    _git(w.priv, "add", "-A"); _git(w.priv, "commit", "-qm", "init")

    pub_dir, priv_dir = w.pub, w.priv
    if swap_paths:
        pub_dir, priv_dir = w.priv, w.pub
    (w.src / ".ssp.env").write_text(
        f'SSP_PUBLIC_DIR="{pub_dir}"\nSSP_PRIVATE_DIR="{priv_dir}"\n')
    return w


def run_update(w: World, *args):
    return subprocess.run(["bash", str(w.script), *args],
                          env=_GIT_ENV, capture_output=True, text=True)


def snapshot(*dirs: Path):
    """Map of relative path -> content hash, ignoring .git internals."""
    import hashlib
    out = {}
    for d in dirs:
        for p in sorted(d.rglob("*")):
            if p.is_file() and ".git" not in p.parts:
                rel = f"{d.name}/{p.relative_to(d)}"
                out[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


@pytest.fixture
def world(tmp_path):
    return build_world(tmp_path)


# ---------------------------------------------------------------- --dry-run
def test_dry_run_happy_path_exits_zero_and_reports_both_repos(world):
    r = run_update(world, "--dry-run")
    assert r.returncode == 0, r.stderr + r.stdout
    out = r.stdout
    assert "DRY RUN" in out
    # per-repo resolved paths + origins (Invariant D inputs)
    assert "PUBLIC" in out and "PRIVATE" in out
    assert "securitysight.git" in out and "securitysight-private.git" in out
    # the exclude list actually applied to each side is printed
    assert "context.md" in out          # public side
    assert "config/" in out             # private side
    assert "all invariants (A–D) passed" in out


def test_dry_run_mutates_nothing(world):
    before = snapshot(world.src, world.pub, world.priv)
    pub_head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=world.pub,
                              env=_GIT_ENV, capture_output=True, text=True).stdout
    priv_head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=world.priv,
                               env=_GIT_ENV, capture_output=True, text=True).stdout

    r = run_update(world, "--dry-run")
    assert r.returncode == 0

    after = snapshot(world.src, world.pub, world.priv)
    assert before == after, "dry-run must not write any file"
    pub_head2 = subprocess.run(["git", "rev-parse", "HEAD"], cwd=world.pub,
                               env=_GIT_ENV, capture_output=True, text=True).stdout
    priv_head2 = subprocess.run(["git", "rev-parse", "HEAD"], cwd=world.priv,
                                env=_GIT_ENV, capture_output=True, text=True).stdout
    assert pub_head == pub_head2 and priv_head == priv_head2, "no commits in dry-run"


# ---------------------------------------------- one deliberate violation each
def test_invariant_A_context_md_to_public_aborts(tmp_path):
    # simulate near-miss #2: the public `context.md` exclude got dropped
    w = build_world(tmp_path, script_replace=("--exclude='context.md'", ""))
    r = run_update(w, "--dry-run")
    assert r.returncode != 0
    assert "INVARIANT A VIOLATED" in r.stderr
    assert "context.md" in r.stderr


def test_invariant_B_real_watchlist_to_public_aborts(tmp_path):
    # the build carries a REAL (non-.example) watchlist; only demo may go public
    w = build_world(tmp_path, real_watchlist=True)
    r = run_update(w, "--dry-run")
    assert r.returncode != 0
    assert "INVARIANT B VIOLATED" in r.stderr
    assert "globex.io" in r.stderr


def test_invariant_C_private_config_clobber_aborts(tmp_path):
    # simulate near-miss #1: the private `config/` exclude got inverted/dropped
    w = build_world(tmp_path, script_replace=("--exclude='config/'", ""))
    r = run_update(w, "--dry-run")
    assert r.returncode != 0
    assert "INVARIANT C VIOLATED" in r.stderr
    assert "config/" in r.stderr


def test_invariant_D_swapped_remotes_aborts(tmp_path):
    # .ssp.env points public->private clone and vice versa
    w = build_world(tmp_path, swap_paths=True)
    r = run_update(w, "--dry-run")
    assert r.returncode != 0
    assert "INVARIANT D VIOLATED" in r.stderr
    assert "swapped" in r.stderr


# ------------------------------------------------------------- real run flow
def test_real_run_happy_path_pushes_and_preserves_invariants(world):
    r = run_update(world, "--yes")
    assert r.returncode == 0, r.stderr + r.stdout
    assert "pushed to PUBLIC" in r.stdout and "pushed to PRIVATE" in r.stdout

    pub_files = subprocess.run(["git", "ls-files"], cwd=world.pub,
                               env=_GIT_ENV, capture_output=True, text=True).stdout
    assert "app.py" in pub_files
    assert "context.md" not in pub_files                 # A held
    assert "demo.example" in (world.pub / "config" / "companies.yaml").read_text()  # B held

    # private kept its real watchlist (config/ excluded) and context.md
    assert "globex.io" in (world.priv / "config" / "companies.yaml").read_text()  # C held
    assert (world.priv / "context.md").exists()
    assert (world.priv / "app.py").exists()              # code still overlaid


def test_real_run_blocked_by_guard_copies_nothing(tmp_path):
    w = build_world(tmp_path, swap_paths=True)
    r = run_update(w, "--yes")
    assert r.returncode != 0
    assert "INVARIANT D VIOLATED" in r.stderr
    assert "Aborting" in r.stderr
    # the source build's app.py must not have been copied into either clone
    assert not (w.pub / "app.py").exists()
    assert not (w.priv / "app.py").exists()
