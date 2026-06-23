#!/usr/bin/env bash
#
# update_repos.sh — push the current build to BOTH GitHub repos.
#
#   public  (securitysight)          : full overlay, keeps demo config/
#   private (securitysight-private)  : code only — preserves your real
#                                      config/, .env and data/
#
# Source of the new code = the directory this script lives in.
# Targets = your local clones, read from .ssp.env (SSP_PUBLIC_DIR / SSP_PRIVATE_DIR).
# Credentials are NEVER handled here: each `git push` lets git prompt you.
#
# Safety: every run (real OR --dry-run) first checks four invariants that make
# the "wrong path / inverted exclude" bug class impossible to commit silently:
#   A  public overlay must not carry context.md (names the target org)
#   B  public overlay must not carry a REAL watchlist (only demo .example config)
#   C  private overlay must not touch config/, .env or data/
#   D  each clone's `origin` must point at the repo its path claims to be
# A violation aborts with a nonzero exit before a single file is copied.
#
# Usage:  ./update_repos.sh [-m "commit message"] [--yes] [--dry-run]
#
#   --dry-run   show, per repo, the exact overlay diff + the exclude list being
#               applied + the resolved target paths and origin remotes, run the
#               invariant checks, then exit WITHOUT writing/committing/pushing.
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd -P)"
cd "$ROOT"
[ -f "$ROOT/.ssp.env" ] && . "$ROOT/.ssp.env"

PUBLIC_DIR="${SSP_PUBLIC_DIR:-}"
PRIVATE_DIR="${SSP_PRIVATE_DIR:-}"

# Discriminator that tells the private repo apart from the public one in an
# `origin` URL. Override in .ssp.env if your repos aren't named *-private.
PRIV_PAT="${SSP_PRIVATE_REPO_PATTERN:-private}"

MSG=""
ASSUME_YES=0
DRY_RUN=0
while [ $# -gt 0 ]; do
  case "$1" in
    -m|--message) MSG="$2"; shift 2 ;;
    --yes|-y)     ASSUME_YES=1; shift ;;
    --dry-run|-n) DRY_RUN=1; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

VER="$(grep -E '__version__' pcrm/__init__.py | sed -E 's/.*"([^"]+)".*/\1/' || true)"
[ -z "$MSG" ] && MSG="Sync to v${VER:-unknown}"

die()  { echo "ERROR: $*" >&2; exit 1; }
confirm() {
  [ "$ASSUME_YES" = "1" ] && return 0
  read -r -p "$1 [y/N] " a; [ "$a" = "y" ] || [ "$a" = "Y" ]
}

[ -n "$PUBLIC_DIR" ]  || die "SSP_PUBLIC_DIR not set — copy .ssp.env.example to .ssp.env and fill it in."
[ -n "$PRIVATE_DIR" ] || die "SSP_PRIVATE_DIR not set — see .ssp.env.example."
[ -d "$PUBLIC_DIR/.git" ]  || die "$PUBLIC_DIR is not a git clone."
[ -d "$PRIVATE_DIR/.git" ] || die "$PRIVATE_DIR is not a git clone."
command -v rsync >/dev/null 2>&1 || die "rsync is required (it ships with macOS)."

# files/dirs that must never be copied between trees
COMMON_EXCLUDES=(--exclude='.git/' --exclude='.env' --exclude='data/'
                 --exclude='data.bak.*' --exclude='.ssp.env*' --exclude='.venv/'
                 --exclude='__pycache__/' --exclude='*.pyc' --exclude='.pytest_cache/'
                 --exclude='build/' --exclude='dist/')

# Per-side exclude lists, resolved once so the guards and the rsync that runs
# share the EXACT same flags (an inverted/edited flag therefore shows up in both
# the dry-run report and the invariant checks — nothing is hardcoded twice).
PUBLIC_EXCLUDES=("${COMMON_EXCLUDES[@]}" --exclude='context.md')
PRIVATE_EXCLUDES=("${COMMON_EXCLUDES[@]}" --exclude='config/')

# --- overlay introspection (no mutation) ---------------------------------

# Print, one per line, every relative path the overlay WOULD write to a target,
# given a side's real excludes. Derived by syncing into a throwaway empty dir,
# so it reflects the filter exactly and never touches a real clone.
overlay_allowed() {            # args: the side's exclude flags
  local tmp; tmp="$(mktemp -d)"
  rsync -an --out-format='%n' "$@" "$ROOT"/ "$tmp"/ 2>/dev/null || true
  rm -rf "$tmp"
}

# A domain token is "demo-safe" if it lives in an RFC-2606/6761 reserved space
# (.example / .test / .invalid / .localhost / example.{com,net,org}).
is_demo_domain() {
  case "$1" in
    *.example|*.example.com|*.example.net|*.example.org) return 0 ;;
    example.com|example.net|example.org)                 return 0 ;;
    *.test|*.invalid|*.localhost|localhost)              return 0 ;;
    *) return 1 ;;
  esac
}

# Echo the first real (non-demo) domain found in a companies watchlist, ignoring
# comments. Empty output ⇒ the file is pure demo data and safe for public.
first_real_domain() {          # arg: path to companies.yaml
  local f="$1" d
  [ -f "$f" ] || return 0
  while read -r d; do
    is_demo_domain "$d" || { printf '%s' "$d"; return 0; }
  done < <(sed -E 's/#.*$//' "$f" \
             | grep -oiE '([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}' \
             | sort -u)
}

# --- invariant guards -----------------------------------------------------

GUARD_FAILED=0
guard_fail() {                 # args: <letter> <message>
  echo "  ✗ INVARIANT $1 VIOLATED: $2" >&2
  GUARD_FAILED=1
}

PUBLIC_ORIGIN="$(cd "$PUBLIC_DIR"  && git remote get-url origin 2>/dev/null || true)"
PRIVATE_ORIGIN="$(cd "$PRIVATE_DIR" && git remote get-url origin 2>/dev/null || true)"

# Reduce an origin URL to its repository name (last path/scp component, no .git),
# so the identity check compares repo names — not the arbitrary directory the
# clone happens to live in (e.g. a tempdir under /private/var on macOS).
reponame() {
  local u="${1%/}"
  u="${u##*/}"; u="${u##*:}"; printf '%s' "${u%.git}"
}

run_guards() {
  GUARD_FAILED=0
  local pub_set priv_set
  pub_set="$(overlay_allowed "${PUBLIC_EXCLUDES[@]}")"
  priv_set="$(overlay_allowed "${PRIVATE_EXCLUDES[@]}")"

  # A — no org leak to public
  if printf '%s\n' "$pub_set" | grep -qx 'context.md'; then
    guard_fail A "public overlay would include context.md (it names the target org)"
  fi

  # B — no real watchlist to public: only demo (.example) config may go public
  if printf '%s\n' "$pub_set" | grep -qx 'config/companies.yaml'; then
    local real; real="$(first_real_domain "$ROOT/config/companies.yaml")"
    [ -n "$real" ] && guard_fail B \
      "public overlay would publish a REAL watchlist (config/companies.yaml contains '$real'; only .example demo data may go public)"
  fi

  # C — no clobber of private state: nothing under config/, .env or data/
  local bad
  bad="$(printf '%s\n' "$priv_set" | grep -E '^(config/|\.env$|data/)' || true)"
  if [ -n "$bad" ]; then
    guard_fail C "private overlay would write protected paths:$(printf ' %s' $bad)"
  fi

  # D — remote identity (the keystone): each path must be the repo it claims.
  # Compare the repo NAME (not the full URL) against the private discriminator.
  local pub_repo priv_repo
  pub_repo="$(reponame "$PUBLIC_ORIGIN")"
  priv_repo="$(reponame "$PRIVATE_ORIGIN")"
  if [ -z "$PUBLIC_ORIGIN" ]; then
    guard_fail D "public clone ($PUBLIC_DIR) has no 'origin' remote"
  elif printf '%s' "$pub_repo" | grep -qi "$PRIV_PAT"; then
    guard_fail D "public path's origin ($PUBLIC_ORIGIN) is the PRIVATE repo '$pub_repo' (matches /$PRIV_PAT/i) — paths look swapped"
  fi
  if [ -z "$PRIVATE_ORIGIN" ]; then
    guard_fail D "private clone ($PRIVATE_DIR) has no 'origin' remote"
  elif ! printf '%s' "$priv_repo" | grep -qi "$PRIV_PAT"; then
    guard_fail D "private path's origin ($PRIVATE_ORIGIN) is '$priv_repo', which does NOT look like the PRIVATE repo (no /$PRIV_PAT/i) — paths look swapped"
  fi

  return $GUARD_FAILED
}

# --- dry-run reporting ----------------------------------------------------

print_excludes() {             # args: exclude flags — print only the patterns
  local x; for x in "$@"; do
    case "$x" in --exclude=*) echo "      - ${x#--exclude=}" ;; esac
  done
}

print_overlay_diff() {         # args: <target> <exclude flags...>
  local target="$1"; shift
  local lines added changed
  # --checksum so a same-size content change is still reported; -n => no writes.
  lines="$(rsync -ainc --out-format='%i %n' "$@" "$ROOT"/ "$target"/ 2>/dev/null || true)"
  added="$(printf '%s\n'   "$lines" | awk '$1 ~ /^>f/ &&  $1 ~ /\+\+\+\+/ {print "      + " $2}')"
  changed="$(printf '%s\n' "$lines" | awk '$1 ~ /^>f/ && !($1 ~ /\+\+\+\+/) {print "      ~ " $2}')"
  echo "    added:"
  [ -n "$added" ]   && printf '%s\n' "$added"   || echo "      (none)"
  echo "    changed:"
  [ -n "$changed" ] && printf '%s\n' "$changed" || echo "      (none)"
  echo "    deleted:"
  echo "      (none — overlay is additive; it never deletes from the target)"
}

dry_run_report() {
  echo
  echo "===================  DRY RUN — no files will be written  ==================="
  echo
  echo "PUBLIC  (securitysight)"
  echo "    path   : $PUBLIC_DIR"
  echo "    origin : ${PUBLIC_ORIGIN:-<none>}"
  echo "    excludes applied:"
  print_excludes "${PUBLIC_EXCLUDES[@]}"
  print_overlay_diff "$PUBLIC_DIR" "${PUBLIC_EXCLUDES[@]}"
  echo
  echo "PRIVATE (securitysight-private)"
  echo "    path   : $PRIVATE_DIR"
  echo "    origin : ${PRIVATE_ORIGIN:-<none>}"
  echo "    excludes applied:"
  print_excludes "${PRIVATE_EXCLUDES[@]}"
  print_overlay_diff "$PRIVATE_DIR" "${PRIVATE_EXCLUDES[@]}"
  echo
}

# --- real push ------------------------------------------------------------

sync_and_push() {
  local target="$1" label="$2"; shift 2
  local excludes=("$@")
  local tgt_real; tgt_real="$(cd "$target" && pwd -P)"

  echo
  echo "=================  $label  ================="
  echo "  target : $target"
  echo "  remote : $(cd "$target" && git remote get-url origin 2>/dev/null || echo '?')"
  echo "  commit : $MSG"

  if [ "$tgt_real" = "$ROOT" ]; then
    echo "  (target is the source dir — committing in place, no copy)"
  else
    rsync -a "${excludes[@]}" "$ROOT"/ "$target"/
  fi

  ( cd "$target"
    git add -A
    if git diff --cached --quiet; then
      echo "  no changes to commit — already up to date."
      exit 0
    fi
    echo "  --- changes ---"
    git status --short
    echo "  ---------------"
    if confirm "  Commit and push these to $label?"; then
      git commit -q -m "$MSG"
      echo "  pushing (git will prompt for credentials if needed)…"
      git push origin HEAD
      echo "  ✓ pushed to $label."
    else
      echo "  skipped $label (working tree staged but not committed)."
    fi
  )
}

# --- main -----------------------------------------------------------------

echo "Updating both repos to: $MSG"
echo "Source of code: $ROOT"

if [ "$DRY_RUN" = "1" ]; then
  dry_run_report
  echo "Invariant checks:"
  if run_guards; then
    echo "  ✓ all invariants (A–D) passed."
    echo
    echo "Dry run only — nothing was written, committed, or pushed. Exit 0."
    exit 0
  else
    echo >&2
    echo "Dry run aborted: one or more invariants failed (see above)." >&2
    exit 1
  fi
fi

# Real run: guards gate the push and must pass before anything is copied.
echo
echo "Checking invariants before any write…"
if run_guards; then
  echo "  ✓ all invariants (A–D) passed."
else
  echo >&2
  echo "Aborting: invariant violation — refusing to copy/commit/push anything." >&2
  echo "Re-run with --dry-run to inspect the resolved paths, excludes and diff." >&2
  exit 1
fi

# PUBLIC first; overlay everything incl. demo config, but NOT context.md.
sync_and_push "$PUBLIC_DIR"  "PUBLIC (securitysight)"          "${PUBLIC_EXCLUDES[@]}"
# PRIVATE second; preserve its real config/, keep context.md.
sync_and_push "$PRIVATE_DIR" "PRIVATE (securitysight-private)" "${PRIVATE_EXCLUDES[@]}"

echo
echo "Done."
