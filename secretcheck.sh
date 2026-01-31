#!/usr/bin/env bash
set -euo pipefail

# prerequisites:
# apt install gitleaks
# pipx install trufflehog

# secretcheck.sh
#
# Modes:
#   Interactive (default):
#     ./secretcheck.sh
#       -> stops on non-allowlisted findings, asks you to clean, re-runs step until clean
#
#   CI / testsuite mode:
#     ./secretcheck.sh --fail-all
#       -> fails immediately on first non-allowlisted finding, no interaction
#
# Allowlist:
#   .secretcheck_allowed in repo root (gitignore-style patterns), BUT as a WHITELIST.
#   Allowlist is re-read on every step run (including repeats).
#
# Extras:
#   --print-allowlisted
#     prints what was ignored by allowlist per step
#
#   --init-allowlist
#     creates .secretcheck_allowed with a commented template if it doesn't exist
#
# Optional env vars:
#   REPORT_DIR=.secretcheck
#   SKIP_TRUFFLEHOG=1
#   RUN_BONUS=1
#
# Exit codes:
#   0  success (all clean)
#   2  missing tool(s)
#   3  user aborted (interactive mode)

REPORT_DIR="${REPORT_DIR:-.secretcheck}"
SKIP_TRUFFLEHOG="${SKIP_TRUFFLEHOG:-0}"
RUN_BONUS="${RUN_BONUS:-0}"

FAIL_ALL=0
PRINT_ALLOWLISTED=0
INIT_ALLOWLIST=0

for arg in "${@:-}"; do
  case "$arg" in
    --fail-all) FAIL_ALL=1 ;;
    --print-allowlisted) PRINT_ALLOWLISTED=1 ;;
    --init-allowlist) INIT_ALLOWLIST=1 ;;
    --bonus) RUN_BONUS=1 ;;
    *) ;;
  esac
done

die() { echo "ERROR: $*" >&2; exit 1; }
is_git_repo() { git rev-parse --is-inside-work-tree >/dev/null 2>&1; }
need_cmd() { command -v "$1" >/dev/null 2>&1; }

pause_for_user() {
  echo
  echo "There were findings (not allowlisted)."
  echo "1) Rotate secrets if any are real (revoke/replace)."
  echo "2) Clean the repo (remove secrets, rewrite history if needed)."
  echo "3) Optionally add false-positive paths to .secretcheck_allowed."
  echo
  read -r -p "Type 'continue' to re-run this step, anything else to abort: " ans
  [[ "$ans" == "continue" ]] || exit 3
}

if ! is_git_repo; then
  die "Run this from inside a git repository."
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

ALLOW_FILE="$REPO_ROOT/.secretcheck_allowed"
mkdir -p "$REPORT_DIR"

if [[ "$INIT_ALLOWLIST" == "1" ]] && [[ ! -f "$ALLOW_FILE" ]]; then
  cat >"$ALLOW_FILE" <<'EOF'
# .secretcheck_allowed
#
# Gitignore-style patterns, but used as a WHITELIST for secretcheck.sh.
# Any finding that originates from a matching path is treated as allowed.
#
# Use this ONLY for known false positives (e.g., docs/examples, test fixtures),
# never for real secrets.
#
# Examples:
# docs/examples/keys.txt
# test/fixtures/**
# **/.env.example
#
# Tip:
# Prefer narrow patterns (single file) over broad ones (whole folders).
EOF
  echo "Created allowlist template: $ALLOW_FILE"
  echo
fi

echo "Repo: $REPO_ROOT"
echo "Reports: $REPORT_DIR"
[[ "$FAIL_ALL" == "1" ]] && echo "Mode: FAIL-ALL (non-interactive)"
[[ "$PRINT_ALLOWLISTED" == "1" ]] && echo "Allowlist reporting: ON"
if [[ -f "$ALLOW_FILE" ]]; then
  echo "Allowlist: $ALLOW_FILE (re-read each step run)"
else
  echo "Allowlist: (none) -> create .secretcheck_allowed or run with --init-allowlist"
fi
echo

missing=0
if ! need_cmd gitleaks; then
  echo "Missing: gitleaks"
  missing=1
fi
if [[ "$SKIP_TRUFFLEHOG" != "1" ]] && ! need_cmd trufflehog; then
  echo "Missing: trufflehog (set SKIP_TRUFFLEHOG=1 to skip)"
  missing=1
fi
if ! need_cmd python3; then
  echo "Missing: python3 (needed for parsing JSON outputs)"
  missing=1
fi
if [[ "$missing" == "1" ]]; then
  echo
  echo "Install hints:"
  echo "  - gitleaks: https://github.com/gitleaks/gitleaks"
  echo "  - trufflehog: pipx install trufflehog"
  echo "  - python3: your distro package manager"
  exit 2
fi

suggest_allowlist() {
  local paths_file="$1"
  [[ -s "$paths_file" ]] || return 0

  echo
  echo "Suggested .secretcheck_allowed entries (review before using):"

  python3 - "$paths_file" <<'PY'
import os, sys
p=sys.argv[1]
paths=[ln.strip() for ln in open(p,'r',encoding='utf-8',errors='ignore') if ln.strip()]
if not paths:
    sys.exit(0)

uniq=[]
seen=set()
for x in paths:
    if x not in seen:
        seen.add(x); uniq.append(x)
uniq=uniq[:20]

from collections import Counter
folders=Counter()
for x in paths:
    d=os.path.dirname(x)
    if d:
        folders[d]+=1

folder_sugs=[(d,c) for d,c in folders.most_common() if c>=2][:10]

print("# exact paths (most common / first seen)")
for x in uniq:
    print(x)

if folder_sugs:
    print("\n# folder wildcards (use only if you really want to allow everything there)")
    for d,c in folder_sugs:
        print(f"{d}/**  # {c} hits")
PY
  echo
}

run_until_clean() {
  local name="$1"
  local runner="$2"
  local raw_log="$3"
  local paths_all="$4"
  local paths_bad="$5"

  while true; do
    echo "==> $name"
    echo

    # Allowlist is re-read each run because runner calls git check-ignore fresh.
    set +e
    bash -lc "$runner" >"$raw_log" 2>&1
    tool_has_findings_rc=$?
    set -e

    : > "$paths_all"
    : > "$paths_bad"
    [[ -f "$paths_all.tmp" ]] && cat "$paths_all.tmp" > "$paths_all" && rm -f "$paths_all.tmp"
    [[ -f "$paths_bad.tmp" ]] && cat "$paths_bad.tmp" > "$paths_bad" && rm -f "$paths_bad.tmp"

    if [[ $tool_has_findings_rc -eq 0 ]]; then
      echo "PASS: $name"
      echo
      return 0
    fi

    if [[ ! -s "$paths_bad" ]]; then
      echo "PASS: $name (findings exist, but all are allowlisted)"
      if [[ "$PRINT_ALLOWLISTED" == "1" ]] && [[ -s "$paths_all" ]]; then
        echo "---- allowlisted paths (seen by tool): $paths_all ----"
        cat "$paths_all" || true
        echo "-----------------------------------------------------"
      fi
      echo
      return 0
    fi

    echo "FAIL: $name (non-allowlisted findings)"
    echo "---- non-allowlisted paths: $paths_bad ----"
    cat "$paths_bad" || true
    echo "------------------------------------------"

    if [[ "$PRINT_ALLOWLISTED" == "1" ]] && [[ -s "$paths_all" ]]; then
      echo "---- allowlisted paths (ignored): ----"
      python3 - "$paths_all" "$paths_bad" <<'PY'
import sys
a=set([l.strip() for l in open(sys.argv[1]) if l.strip()])
b=set([l.strip() for l in open(sys.argv[2]) if l.strip()])
only=sorted(a-b)
print("\n".join(only))
PY
      echo "--------------------------------------"
    fi

    suggest_allowlist "$paths_bad"

    echo "---- last 80 lines of raw log: $raw_log ----"
    tail -n 80 "$raw_log" || true
    echo "-------------------------------------------"

    if [[ "$FAIL_ALL" == "1" ]]; then
      echo "FAIL-ALL active -> aborting."
      exit 1
    fi

    pause_for_user
    echo
  done
}

# --------------------------------------------------
# Step 1: gitleaks (full history)
# --------------------------------------------------
GITLEAKS_LOG="$REPORT_DIR/gitleaks.log"
GITLEAKS_JSON="$REPORT_DIR/gitleaks.json"
GITLEAKS_ALL="$REPORT_DIR/gitleaks.paths_all.txt"
GITLEAKS_BAD="$REPORT_DIR/gitleaks.paths_bad.txt"

run_until_clean \
  "gitleaks (full history)" \
  "
  gitleaks detect --source . --log-opts='--all' --redact --report-format json --report-path '$GITLEAKS_JSON' --verbose || true

  python3 - '$GITLEAKS_JSON' >'$GITLEAKS_ALL.tmp' 2>/dev/null <<'PY'
import json, sys, os
jpath=sys.argv[1]
if not os.path.isfile(jpath):
    sys.exit(0)
try:
    data=json.load(open(jpath,'r',encoding='utf-8'))
except Exception:
    sys.exit(0)
paths=[]
if isinstance(data,list):
    for f in data:
        if isinstance(f,dict):
            p=f.get('File') or f.get('file')
            if p:
                paths.append(p)
seen=set(); out=[]
for p in paths:
    if p not in seen:
        seen.add(p); out.append(p)
print('\\n'.join(out))
PY

  python3 - '$GITLEAKS_ALL.tmp' '$ALLOW_FILE' >'$GITLEAKS_BAD.tmp' <<'PY'
import sys, os, subprocess
allfile, allow = sys.argv[1], sys.argv[2]
lines=[l.strip() for l in open(allfile,'r',encoding='utf-8',errors='ignore') if l.strip()]

def allowlisted(path: str) -> bool:
    if not allow or not os.path.isfile(allow):
        return False
    r=subprocess.run(['git','check-ignore','--no-index','--exclude-from',allow,'--',path],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode==0

bad=[p for p in lines if not allowlisted(p)]
print('\\n'.join(bad))
PY

  python3 - '$GITLEAKS_JSON' <<'PY'
import json, sys, os
p=sys.argv[1]
if not os.path.isfile(p):
    sys.exit(0)
try:
    d=json.load(open(p,'r',encoding='utf-8'))
except Exception:
    sys.exit(0)
sys.exit(1 if isinstance(d,list) and len(d)>0 else 0)
PY
  " \
  "$GITLEAKS_LOG" \
  "$GITLEAKS_ALL" \
  "$GITLEAKS_BAD"

# --------------------------------------------------
# Step 2: trufflehog (git history)
# --------------------------------------------------
if [[ "$SKIP_TRUFFLEHOG" != "1" ]]; then
  TRUFFLEHOG_LOG="$REPORT_DIR/trufflehog.log"
  TRUFFLEHOG_JSONL="$REPORT_DIR/trufflehog.jsonl"
  TRUFFLEHOG_ALL="$REPORT_DIR/trufflehog.paths_all.txt"
  TRUFFLEHOG_BAD="$REPORT_DIR/trufflehog.paths_bad.txt"

  run_until_clean \
    "trufflehog (git history)" \
    "
    trufflehog git file://'$REPO_ROOT' --only-verified=false --json >'$TRUFFLEHOG_JSONL' 2>/dev/null || true

    python3 - '$TRUFFLEHOG_JSONL' >'$TRUFFLEHOG_ALL.tmp' <<'PY'
import sys, os, json
p=sys.argv[1]
if not os.path.isfile(p):
    sys.exit(0)
paths=[]
with open(p,'r',encoding='utf-8',errors='ignore') as f:
    for line in f:
        line=line.strip()
        if not line:
            continue
        try:
            obj=json.loads(line)
        except Exception:
            continue
        sm=obj.get('SourceMetadata') or {}
        data=sm.get('Data') or {}
        git=data.get('Git') or {}
        path = git.get('File') or git.get('file') or data.get('File') or data.get('file') or obj.get('path')
        if path:
            paths.append(path)
seen=set(); out=[]
for x in paths:
    if x not in seen:
        seen.add(x); out.append(x)
print('\\n'.join(out))
PY

    python3 - '$TRUFFLEHOG_ALL.tmp' '$ALLOW_FILE' >'$TRUFFLEHOG_BAD.tmp' <<'PY'
import sys, os, subprocess
allfile, allow = sys.argv[1], sys.argv[2]
lines=[l.strip() for l in open(allfile,'r',encoding='utf-8',errors='ignore') if l.strip()]

def allowlisted(path: str) -> bool:
    if not allow or not os.path.isfile(allow):
        return False
    r=subprocess.run(['git','check-ignore','--no-index','--exclude-from',allow,'--',path],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode==0

bad=[p for p in lines if not allowlisted(p)]
print('\\n'.join(bad))
PY

    python3 - '$TRUFFLEHOG_JSONL' <<'PY'
import sys, os
p=sys.argv[1]
if not os.path.isfile(p):
    sys.exit(0)
with open(p,'r',encoding='utf-8',errors='ignore') as f:
    for line in f:
        if line.strip():
            sys.exit(1)
sys.exit(0)
PY
    " \
    "$TRUFFLEHOG_LOG" \
    "$TRUFFLEHOG_ALL" \
    "$TRUFFLEHOG_BAD"
else
  echo "SKIP: trufflehog"
  echo
fi

# --------------------------------------------------
# Bonus checks
# --------------------------------------------------
if [[ "$RUN_BONUS" != "1" ]]; then
  echo "SKIP: bonus checks (opt-in via --bonus or RUN_BONUS=1)"
  echo
else
  # Step 3: keyword grep in working tree
  BONUS_GREP_LOG="$REPORT_DIR/bonus_grep.log"
  BONUS_GREP_ALL="$REPORT_DIR/bonus_grep.paths_all.txt"
  BONUS_GREP_BAD="$REPORT_DIR/bonus_grep.paths_bad.txt"

  run_until_clean \
    "bonus grep (working tree obvious patterns)" \
    "
    set +e
    git grep -nEi \"(api[_-]?key|secret|token|passwd|password|private[_-]?key|BEGIN (RSA|OPENSSH) PRIVATE KEY)\" >'$BONUS_GREP_LOG' 2>&1
    rc=\$?
    set -e

    python3 - '$BONUS_GREP_LOG' >'$BONUS_GREP_ALL.tmp' <<'PY'
import sys, os
p=sys.argv[1]
if not os.path.isfile(p):
    sys.exit(0)
paths=[]
for ln in open(p,'r',encoding='utf-8',errors='ignore'):
    ln=ln.strip()
    if not ln or ':' not in ln:
        continue
    path=ln.split(':',1)[0].strip()
    if path:
        paths.append(path)
seen=set(); out=[]
for x in paths:
    if x not in seen:
        seen.add(x); out.append(x)
print('\\n'.join(out))
PY

    python3 - '$BONUS_GREP_ALL.tmp' '$ALLOW_FILE' >'$BONUS_GREP_BAD.tmp' <<'PY'
import sys, os, subprocess
allfile, allow = sys.argv[1], sys.argv[2]
lines=[l.strip() for l in open(allfile,'r',encoding='utf-8',errors='ignore') if l.strip()]

def allowlisted(path: str) -> bool:
    if not allow or not os.path.isfile(allow):
        return False
    r=subprocess.run(['git','check-ignore','--no-index','--exclude-from',allow,'--',path],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode==0

bad=[p for p in lines if not allowlisted(p)]
print('\\n'.join(bad))
PY

    if [[ \$rc -eq 1 ]]; then exit 0; else exit 1; fi
    " \
    "$BONUS_GREP_LOG" \
    "$BONUS_GREP_ALL" \
    "$BONUS_GREP_BAD"

  # Step 4: risky filetypes ever in history
  BONUS_TYPES_LOG="$REPORT_DIR/bonus_history_filetypes.log"
  BONUS_TYPES_ALL="$REPORT_DIR/bonus_history_filetypes.paths_all.txt"
  BONUS_TYPES_BAD="$REPORT_DIR/bonus_history_filetypes.paths_bad.txt"

  run_until_clean \
    "bonus history filetype check (.env/.pem/.p12/...)" \
    "
    set +e
    git rev-list --all | while read -r c; do
      git show \"\$c\" --name-only --pretty=format: 2>/dev/null
      echo
    done | grep -nEi \"\\.(env|pem|p12|pfx|key|kdb|keystore)\$\" >'$BONUS_TYPES_LOG' 2>&1
    rc=\$?
    set -e

    python3 - '$BONUS_TYPES_LOG' >'$BONUS_TYPES_ALL.tmp' <<'PY'
import sys, os
p=sys.argv[1]
if not os.path.isfile(p):
    sys.exit(0)
paths=[]
for ln in open(p,'r',encoding='utf-8',errors='ignore'):
    ln=ln.strip()
    if not ln or ':' not in ln:
        continue
    _, path = ln.split(':',1)
    path=path.strip()
    if path:
        paths.append(path)
seen=set(); out=[]
for x in paths:
    if x not in seen:
        seen.add(x); out.append(x)
print('\\n'.join(out))
PY

    python3 - '$BONUS_TYPES_ALL.tmp' '$ALLOW_FILE' >'$BONUS_TYPES_BAD.tmp' <<'PY'
import sys, os, subprocess
allfile, allow = sys.argv[1], sys.argv[2]
lines=[l.strip() for l in open(allfile,'r',encoding='utf-8',errors='ignore') if l.strip()]

def allowlisted(path: str) -> bool:
    if not allow or not os.path.isfile(allow):
        return False
    r=subprocess.run(['git','check-ignore','--no-index','--exclude-from',allow,'--',path],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode==0

bad=[p for p in lines if not allowlisted(p)]
print('\\n'.join(bad))
PY

    if [[ \$rc -eq 1 ]]; then exit 0; else exit 1; fi
    " \
    "$BONUS_TYPES_LOG" \
    "$BONUS_TYPES_ALL" \
    "$BONUS_TYPES_BAD"
fi

echo "✅ ALL CHECKS CLEAN (or allowlisted)"
echo "Reports saved in: $REPORT_DIR"
