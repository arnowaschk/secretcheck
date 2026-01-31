#!/usr/bin/env bash
set -euo pipefail

# apt install gitleaks
# pipx install trufflehog

# Modes:
#   Interactive (default):
#     ./secretcheck.sh
#       -> stops on findings, asks to "retry" (re-runs step after some fixes) or "skip" (goes to next step)
#
#   CI / testsuite mode:
#     ./secretcheck.sh --fail-all
#       -> fails immediately on first non-allowlisted finding, no interaction
#
# Allowlist:
#   .secretcheck_allowed in repo root (gitignore-style patterns), BUT as a WHITELIST.
#   Allowlist is re-read on every step run (including repeats).
#   Use this ONLY for known false positives (e.g., docs/examples, test fixtures),
#   never for real secrets.
#
# Extras:
#   --print-allowlisted
#     prints what was ignored by allowlist per step
#
#   --init-allowlist
#     creates .secretcheck_allowed with a commented template if it doesn't exist
#
# Optional env vars and their defaults:
#   REPORT_DIR=.secretcheck
#   SKIP_TRUFFLEHOG=0
#   RUN_BONUS=0
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
SKIPPED_ANY=0

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
  echo "You should consider:"
  echo "1) Rotating secrets if any are real (revoke/replace)."
  echo "2) Cleaning the repo (remove secrets, rewrite history if needed)."
  echo "3) Or adding false-positive paths to .secretcheck_allowed."
  echo
  echo "Repo: $REPO_ROOT"
  echo
  read -r -p "Type 'retry' to re-run this step, 'skip' to skip it, anything else to abort: " ans
  if [[ "$ans" == "retry" ]]; then
    return 0
  elif [[ "$ans" == "skip" ]]; then
    return 2
  else
    exit 3
  fi
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
# Use this ONLY for known false positives (e.g., docs/examples, test fixtures),
# never for real secrets.
#
# Examples:
# docs/examples/keys.txt
# test/fixtures/**
# **/.env.example
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
  local warning_msg="${6:-}"

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

    echo "---- last 80 lines of raw log: $raw_log ----"
    python3 - "$raw_log" <<'PY' || true
import sys, os
log_path = sys.argv[1]
if not os.path.exists(log_path): sys.exit(0)
try:
    with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()[-80:]
    trunc = False
    for line in lines:
        line = line.rstrip('\n')
        if len(line) > 300:
            print(line[:300] + ' [TRUNCATED]')
            trunc = True
        else:
            print(line)
    if trunc:
        print("\n[NOTICE] some long lines were truncated")
except:
    pass
PY
    echo "-------------------------------------------"

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

    if [[ -n "$warning_msg" ]]; then
      echo "$warning_msg"
      echo
    fi

    if [[ "$FAIL_ALL" == "1" ]]; then
      echo "FAIL-ALL active -> aborting."
      exit 1
    fi

    set +e
    pause_for_user
    pause_rc=$?
    set -e

    if [[ $pause_rc -eq 2 ]]; then
      echo "SKIPPING: $name (as requested by user)"
      SKIPPED_ANY=1
      echo
      return 0
    fi

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
  gitleaks detect --source . --log-opts='--all' --redact --report-format json --report-path '$GITLEAKS_JSON' --verbose > '$GITLEAKS_LOG.tmp_raw' 2>&1 || true

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

  python3 - '$GITLEAKS_ALL.tmp' '$ALLOW_FILE' "$REPORT_DIR" >'$GITLEAKS_BAD.tmp' <<'PY'
import sys, os
allfile, allow, report_dir = sys.argv[1], sys.argv[2], sys.argv[3]
lines=[l.strip() for l in open(allfile,'r',encoding='utf-8',errors='ignore') if l.strip()]

def allowlisted(path: str) -> bool:
    if report_dir and path.startswith(report_dir): return True
    if not allow or not os.path.isfile(allow): return False
    import fnmatch
    with open(allow, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            pat = line.strip()
            if not pat or pat.startswith('#'): continue
            if fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(path, pat.rstrip('/') + '/*'):
                return True
    return False

bad=[p for p in lines if not allowlisted(p)]
if bad: print('\\n'.join(bad), end='')
PY

  python3 - '$GITLEAKS_LOG.tmp_raw' '$GITLEAKS_BAD.tmp' <<'PY'
import sys, os
log, bad_f = sys.argv[1], sys.argv[2]
bad_set = set([l.strip() for l in open(bad_f, encoding='utf-8', errors='ignore') if l.strip()]) if os.path.exists(bad_f) else set()
if not os.path.exists(log): sys.exit(0)
with open(log, 'r', encoding='utf-8', errors='ignore') as f:
    blocks = f.read().split('\n\n')
    for b in blocks:
        if 'Finding:' in b:
            path = None
            for ln in b.splitlines():
                if ln.strip().startswith('File:'):
                    path = ln.split(':', 1)[1].strip()
                    break
            if path and path not in bad_set: continue
        print(b + '\n')
PY
rm -f '$GITLEAKS_LOG.tmp_raw'

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
  " "$GITLEAKS_LOG" "$GITLEAKS_ALL" "$GITLEAKS_BAD"

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

    python3 - '$TRUFFLEHOG_ALL.tmp' '$ALLOW_FILE' "$REPORT_DIR" >'$TRUFFLEHOG_BAD.tmp' <<'PY'
import sys, os
allfile, allow, report_dir = sys.argv[1], sys.argv[2], sys.argv[3]
lines=[l.strip() for l in open(allfile,'r',encoding='utf-8',errors='ignore') if l.strip()]

def allowlisted(path: str) -> bool:
    if report_dir and path.startswith(report_dir): return True
    if not allow or not os.path.isfile(allow): return False
    import fnmatch
    with open(allow, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            pat = line.strip()
            if not pat or pat.startswith('#'): continue
            if fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(path, pat.rstrip('/') + '/*'):
                return True
    return False

bad=[p for p in lines if not allowlisted(p)]
if bad: print('\\n'.join(bad), end='')
PY

    python3 - '$TRUFFLEHOG_JSONL' '$TRUFFLEHOG_BAD.tmp' <<'PY'
import sys, os, json
jsonl, bad_f = sys.argv[1], sys.argv[2]
bad_set = set([l.strip() for l in open(bad_f, encoding='utf-8', errors='ignore') if l.strip()]) if os.path.exists(bad_f) else set()
if not os.path.exists(jsonl): sys.exit(0)
with open(jsonl, 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try:
            o = json.loads(line)
        except: continue
        sm = o.get('SourceMetadata') or {}
        data = sm.get('Data') or {}
        git = data.get('Git') or {}
        path = git.get('File') or git.get('file') or data.get('File') or data.get('file') or o.get('path')
        if path and path in bad_set:
            print(f'Finding in:  {path}')
            print('Raw:         ' + str(o.get('Raw', o.get('raw', '')))[:100] + '...')
            print('Commit:      ' + str(git.get('Commit') or ''))
            print()
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
    " "$TRUFFLEHOG_LOG" "$TRUFFLEHOG_ALL" "$TRUFFLEHOG_BAD"
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
    git grep -nEi \"(api[_-]?key|secret|token|passwd|password|private[_-]?key|BEGIN (RSA|OPENSSH) PRIVATE KEY)\" >'$BONUS_GREP_LOG.tmp_raw' 2>&1
    rc=\$?
    set -e

    python3 - '$BONUS_GREP_LOG.tmp_raw' >'$BONUS_GREP_ALL.tmp' <<'PY'
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

    python3 - '$BONUS_GREP_ALL.tmp' '$ALLOW_FILE' "$REPORT_DIR" >'$BONUS_GREP_BAD.tmp' <<'PY'
import sys, os
allfile, allow, report_dir = sys.argv[1], sys.argv[2], sys.argv[3]
lines=[l.strip() for l in open(allfile,'r',encoding='utf-8',errors='ignore') if l.strip()]

def allowlisted(path: str) -> bool:
    if report_dir and path.startswith(report_dir): return True
    if not allow or not os.path.isfile(allow): return False
    import fnmatch
    with open(allow, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            pat = line.strip()
            if not pat or pat.startswith('#'): continue
            if fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(path, pat.rstrip('/') + '/*'):
                return True
    return False

bad=[p for p in lines if not allowlisted(p)]
if bad: print('\\n'.join(bad), end='')
PY

    python3 - '$BONUS_GREP_LOG.tmp_raw' '$BONUS_GREP_BAD.tmp' <<'PY'
import sys, os
log, bad_f = sys.argv[1], sys.argv[2]
bad_set = set([l.strip() for l in open(bad_f, encoding='utf-8', errors='ignore') if l.strip()]) if os.path.exists(bad_f) else set()
if not os.path.exists(log): sys.exit(0)
with open(log, 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        if ':' in line:
            path = line.split(':', 1)[0].strip()
            if path in bad_set:
                print(line, end='')
PY
rm -f '$BONUS_GREP_LOG.tmp_raw'

    if [[ \$rc -eq 1 ]]; then exit 0; else exit 1; fi
    " "$BONUS_GREP_LOG" "$BONUS_GREP_ALL" "$BONUS_GREP_BAD" \
    "NOTE: Bonus checks often produce many false positives. They can be helpful but require manual review."

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
    done | grep -nEi \"\\.(env|pem|p12|pfx|key|kdb|keystore)\$\" >'$BONUS_TYPES_LOG.tmp_raw' 2>&1
    rc=\$?
    set -e

    python3 - '$BONUS_TYPES_LOG.tmp_raw' >'$BONUS_TYPES_ALL.tmp' <<'PY'
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

    python3 - '$BONUS_TYPES_ALL.tmp' '$ALLOW_FILE' "$REPORT_DIR" >'$BONUS_TYPES_BAD.tmp' <<'PY'
import sys, os
allfile, allow, report_dir = sys.argv[1], sys.argv[2], sys.argv[3]
lines=[l.strip() for l in open(allfile,'r',encoding='utf-8',errors='ignore') if l.strip()]

def allowlisted(path: str) -> bool:
    if report_dir and path.startswith(report_dir): return True
    if not allow or not os.path.isfile(allow): return False
    import fnmatch
    with open(allow, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            pat = line.strip()
            if not pat or pat.startswith('#'): continue
            if fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(path, pat.rstrip('/') + '/*'):
                return True
    return False

bad=[p for p in lines if not allowlisted(p)]
if bad: print('\\n'.join(bad), end='')
PY

    if [[ \$rc -eq 1 ]]; then exit 0; else exit 1; fi
    " "$BONUS_TYPES_LOG" "$BONUS_TYPES_ALL" "$BONUS_TYPES_BAD" \
    "NOTE: Bonus checks often produce many false positives. They can be helpful but require manual review."
fi

if [[ "$SKIPPED_ANY" == "1" ]]; then
  echo "⚠️ SOME CHECKS HAVE FAILED (see above)"
  echo "Reports saved in: $REPORT_DIR"
  exit 1
else
  echo "✅ ALL CHECKS CLEAN (or allowlisted)"
  echo "Reports saved in: $REPORT_DIR"
fi
