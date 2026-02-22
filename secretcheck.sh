#!/usr/bin/env bash
set -euo pipefail

VERSION="1.0.2"
exec 3>&2

# ============================================================================
# Configuration Constants
# ============================================================================
# These can be overridden by patterns.yml or environment variables

# Display settings
LOG_TAIL_LINES="${LOG_TAIL_LINES:-80}"
MAX_LINE_LENGTH="${MAX_LINE_LENGTH:-300}"
MAX_ALLOWLIST_SUGGESTIONS="${MAX_ALLOWLIST_SUGGESTIONS:-20}"

# Python version requirement
# Python version requirement
MIN_PYTHON_VERSION="${MIN_PYTHON_VERSION:-3.6}"

# Colors (autodetected)
if [[ -t 1 ]] && [[ "${NO_COLOR:-0}" != "1" ]]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  BLUE='\033[0;34m'
  BOLD='\033[1m'
  NC='\033[0m' # No Color
else
  RED=''
  GREEN=''
  YELLOW=''
  BLUE=''
  BOLD=''
  NC=''
fi

# Default patterns for bonus checks (comprehensive defaults)
DEFAULT_GREP_PATTERNS="(api[_-]?key|secret|token|passwd|password|private[_-]?key|BEGIN (RSA|OPENSSH) PRIVATE KEY)"
DEFAULT_FILETYPE_PATTERNS="\.env|\.pem|\.p12|\.pfx|\.key|\.kdb|\.keystore"

# ============================================================================
# Help and Version
# ============================================================================

show_help() {
  cat <<'EOF'
   ____                     _    ____ _               _    
  / ___|  ___  ___ _ __ ___| |_ / ___| |__   ___  ___| | __
  \___ \ / _ \/ __| '__/ _ \ __| |   | '_ \ / _ \/ __| |/ /
   ___) |  __/ (__| | |  __/ |_| |___| | | |  __/ (__|   < 
  |____/ \___|\___|_|  \___|\__|\____|_| |_|\___|\___|_|\_\

SecretCheck - Your paranoid friend who double-checks for secrets in git repos

USAGE:
  secretcheck.sh [OPTIONS]

OPTIONS:
  --help              Show this help message and exit
  --version           Show version information and exit
  --fail-all          CI/CD mode: fail immediately on first finding (non-interactive)
  --bonus             Enable bonus checks (custom patterns, may have false positives)
  --dry-run           Show what would be checked without running tools
  --fast              Fast scan: recently changed files only, skips deep history scans
  --exclude PATTERN   Exclude paths matching glob pattern (can be used multiple times)
  --install-hook      Automated installation of the git pre-commit hook
  --check-deps        Check if required dependencies are installed correctly
  --update            Check for and install script updates from GitHub
  --sarif             Generate a SARIF report for integration with security tabs
  --verbose           Show detailed progress information
  --quiet             Minimize output (errors only)
  --no-color          Disable colorized output
  --print-allowlisted Show paths that were allowlisted
  --init-allowlist    Create a template .secretcheck_allowed file

CONFIGURATION:
  patterns.yml        Optional config file for custom patterns (see README.md)
  .secretcheck_allowed  Allowlist file with glob patterns (supports inline comments)

ENVIRONMENT VARIABLES:
  REPORT_DIR          Where to store reports (default: .secretcheck)
  SKIP_TRUFFLEHOG     Set to 1 to skip trufflehog scan
  RUN_BONUS           Set to 1 to enable bonus checks (same as --bonus)
  FAIL_ALL            Set to 1 for CI mode (same as --fail-all)
  PRINT_ALLOWLISTED   Set to 1 to show allowlisted paths

EXIT CODES:
  0  All checks passed (clean or allowlisted)
  1  Findings detected (fail-all mode or user skipped checks)
  2  Operational error (missing tools, not a git repo, invalid arguments)
  3  User aborted (interactive mode)

EXAMPLES:
  # Interactive scan with bonus checks
  secretcheck.sh --bonus

  # CI/CD mode (fail fast, no interaction)
  secretcheck.sh --fail-all

  # Dry run to see what would be checked
  secretcheck.sh --dry-run

  # Exclude vendor and node_modules
  secretcheck.sh --exclude "vendor/**" --exclude "node_modules/**"

DOCUMENTATION:
  https://github.com/arnowaschk/secretcheck

EOF
}

show_version() {
  echo "SecretCheck version $VERSION"
  echo "Copyright (c) 2026 Arno Waschk"
  echo "License: MIT"
}

# ============================================================================
# Environment Variables and Flags
# ============================================================================

REPORT_DIR="${REPORT_DIR:-.secretcheck}"
SKIP_TRUFFLEHOG="${SKIP_TRUFFLEHOG:-0}"
RUN_BONUS="${RUN_BONUS:-0}"

FAIL_ALL="${FAIL_ALL:-0}"
PRINT_ALLOWLISTED="${PRINT_ALLOWLISTED:-0}"
INIT_ALLOWLIST=0
SKIPPED_ANY=0
DRY_RUN=0
VERBOSE=0
QUIET=0

# Arrays for exclude patterns
declare -a EXCLUDE_PATTERNS=()

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --help) show_help; exit 0 ;;
    --version) show_version; exit 0 ;;
    --fail-all) FAIL_ALL=1 ;;
    --print-allowlisted) PRINT_ALLOWLISTED=1 ;;
    --init-allowlist) INIT_ALLOWLIST=1 ;;
    --bonus) RUN_BONUS=1 ;;
    --dry-run) DRY_RUN=1 ;;
    --verbose) VERBOSE=1 ;;
    --quiet) QUIET=1 ;;
    --exclude)
      if [[ -n "${2:-}" ]]; then
        EXCLUDE_PATTERNS+=("$2")
        shift
      fi
      ;;
    --exclude=*)
      EXCLUDE_PATTERNS+=("${1#*=}")
      ;;
    --no-color) NO_COLOR=1 ;;
    --install-hook) INSTALL_HOOK=1 ;;
    --check-deps) CHECK_DEPS=1 ;;
    --fast) FAST_MODE=1 ;;
    --update) UPDATE_MODE=1 ;;
    --sarif) SARIF_MODE=1 ;;
    -*) 
      echo -e "${RED}ERROR: Unknown option: $1${NC}" >&2
      echo "Run 'secretcheck.sh --help' for usage information." >&2
      exit 2
      ;;
    *)
      # Ignore non-option arguments for now 
      ;;
  esac
  shift
done

# Re-evaluate colors if --no-color was passed late
if [[ "${NO_COLOR:-0}" == "1" ]]; then
  RED='' GREEN='' YELLOW='' BLUE='' BOLD='' NC=''
fi

# ============================================================================
# Utility Functions
# ============================================================================


die() { echo -e "${RED}ERROR: $*${NC}" >&2; exit 2; }
is_git_repo() { git rev-parse --is-inside-work-tree >/dev/null 2>&1; }
need_cmd() { command -v "$1" >/dev/null 2>&1; }

log_verbose() {
  [[ "$VERBOSE" == "1" ]] && echo -e "${BLUE}[VERBOSE] $*${NC}" >&3 || true
}

log_info() {
  [[ "$QUIET" != "1" ]] && echo -e "$*" >&3 || true
}

log_progress() {
  [[ "$QUIET" != "1" ]] && [[ "$DRY_RUN" != "1" ]] && echo -ne "${BLUE}$*${NC}" >&3 || true
}

log_progress_done() {
  [[ "$QUIET" != "1" ]] && [[ "$DRY_RUN" != "1" ]] && echo -e " ${GREEN}done${NC}" >&3 || true
}

# Check Python version
check_python_version() {
  if ! need_cmd python3; then
    return 1
  fi
  
  local py_version
  py_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0.0")
  
  local required_major="${MIN_PYTHON_VERSION%%.*}"
  local required_minor="${MIN_PYTHON_VERSION##*.}"
  local actual_major="${py_version%%.*}"
  local actual_minor="${py_version##*.}"
  
  if [[ "$actual_major" -lt "$required_major" ]] || \
     [[ "$actual_major" -eq "$required_major" && "$actual_minor" -lt "$required_minor" ]]; then
    echo "ERROR: Python $MIN_PYTHON_VERSION or higher required, found $py_version" >&2
    return 1
  fi
  
  log_verbose "Python version: $py_version (>= $MIN_PYTHON_VERSION required)"
  return 0
}

# Load configuration from patterns.yml if it exists
# Load configuration from patterns.yml if it exists
load_config() {
  local config_file="${1:-patterns.yml}"
  
  if [[ ! -f "$config_file" ]]; then
    log_verbose "No $config_file found, using defaults"
    return 0
  fi
  
  log_verbose "Loading configuration from $config_file"
  
  # Parse YAML using Python and read output safely (NO EVAL)
  while IFS='=' read -r key val; do
    case "$key" in
      BONUS_GREP_PATTERNS_FROM_CONFIG) DEFAULT_GREP_PATTERNS="$val" ;;
      BONUS_FILETYPE_PATTERNS_FROM_CONFIG) DEFAULT_FILETYPE_PATTERNS="$val" ;;
      EXCLUDE_PATTERN_FROM_CONFIG) EXCLUDE_PATTERNS+=("$val") ;;
      LOG_TAIL_LINES) LOG_TAIL_LINES="$val" ;;
      MAX_LINE_LENGTH) MAX_LINE_LENGTH="$val" ;;
      MAX_ALLOWLIST_SUGGESTIONS) MAX_ALLOWLIST_SUGGESTIONS="$val" ;;
      MIN_PYTHON_VERSION) MIN_PYTHON_VERSION="$val" ;;
    esac
  done < <(python3 - "$config_file" <<'PY'
import sys, re, os

config_file = sys.argv[1]
if not os.path.exists(config_file):
    sys.exit(0)

with open(config_file, 'r', encoding='utf-8') as f:
    content = f.read()

# Extract bonus_grep_patterns
grep_section = re.search(r'bonus_grep_patterns:\s*\n((?:  - .+\n)+)', content)
if grep_section:
    patterns = re.findall(r'  - ["\']?(.+?)["\']?\s*(?:#.*)?$', grep_section.group(1), re.MULTILINE)
    if patterns:
        print(f"BONUS_GREP_PATTERNS_FROM_CONFIG={'|'.join(f'({p})' for p in patterns)}")

# Extract bonus_filetype_patterns
filetype_section = re.search(r'bonus_filetype_patterns:\s*\n((?:  - .+\n)+)', content)
if filetype_section:
    patterns = re.findall(r'  - ["\']?(.+?)["\']?\s*(?:#.*)?$', filetype_section.group(1), re.MULTILINE)
    if patterns:
        print(f"BONUS_FILETYPE_PATTERNS_FROM_CONFIG={'|'.join(patterns)}")

# Extract exclude_patterns
exclude_section = re.search(r'exclude_patterns:\s*\n((?:  - .+\n)+)', content)
if exclude_section:
    patterns = re.findall(r'  - ["\']?(.+?)["\']?\s*(?:#.*)?$', exclude_section.group(1), re.MULTILINE)
    for p in patterns:
        if p.strip():
            print(f"EXCLUDE_PATTERN_FROM_CONFIG={p}")

# Extract settings
settings_section = re.search(r'settings:\s*\n((?:  \w+:.+\n)+)', content)
if settings_section:
    log_tail = re.search(r'log_tail_lines:\s*(\d+)', settings_section.group(1))
    if log_tail:
        print(f"LOG_TAIL_LINES={log_tail.group(1)}")
    
    max_line = re.search(r'max_line_length:\s*(\d+)', settings_section.group(1))
    if max_line:
        print(f"MAX_LINE_LENGTH={max_line.group(1)}")
    
    max_sugg = re.search(r'max_allowlist_suggestions:\s*(\d+)', settings_section.group(1))
    if max_sugg:
        print(f"MAX_ALLOWLIST_SUGGESTIONS={max_sugg.group(1)}")
    
    min_py = re.search(r'min_python_version:\s*["\']?([0-9.]+)["\']?', settings_section.group(1))
    if min_py:
        print(f"MIN_PYTHON_VERSION={min_py.group(1)}")
PY
)
}

# Self-update function
self_update() {
  log_info "Checking for updates..."
  local temp_script
  temp_script=$(mktemp)
  local url="https://raw.githubusercontent.com/arnowaschk/secretcheck/main/secretcheck.sh"
  
  if ! curl -sSL "$url" -o "$temp_script"; then
    log_info "${RED}Failed to download update.${NC}"
    rm -f "$temp_script"
    exit 1
  fi
  
  if ! bash -n "$temp_script"; then
    log_info "${RED}Downloaded update is corrupt (syntax error). Aborting.${NC}"
    rm -f "$temp_script"
    exit 1
  fi
  
  local new_version
  new_version=$(grep '^VERSION=' "$temp_script" | cut -d'"' -f2)
  
  if [[ "$new_version" == "$VERSION" ]]; then
    log_info "${GREEN}You are already using the latest version ($VERSION).${NC}"
    rm -f "$temp_script"
    exit 0
  fi
  
  log_info "New version available: ${YELLOW}$new_version${NC} (current: $VERSION)"
  read -r -p "Update now? [y/N] " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    cat "$temp_script" > "$0"
    log_info "${GREEN}Updated successfully to $new_version.${NC}"
    rm -f "$temp_script"
    exit 0
  else
    log_info "Update skipped."
    rm -f "$temp_script"
    exit 0
  fi
}

# Check for detached HEAD state
check_git_state() {
  if ! git symbolic-ref -q HEAD >/dev/null 2>&1; then
    log_verbose "WARNING: Repository is in detached HEAD state"
    log_verbose "This may affect history scanning. Consider checking out a branch."
  fi
}

# Validate allowlist patterns
validate_allowlist() {
  local allow_file="$1"
  
  [[ ! -f "$allow_file" ]] && return 0
  
  log_verbose "Validating allowlist patterns in $allow_file"
  
  python3 - "$allow_file" <<'PY' || true
import sys, fnmatch

allow_file = sys.argv[1]
warnings = []

with open(allow_file, 'r', encoding='utf-8', errors='replace') as f:
    for line_num, line in enumerate(f, 1):
        # Remove inline comments
        if '#' in line:
            parts = line.split('#', 1)
            pattern = parts[0].strip()
        else:
            pattern = line.strip()
        
        if not pattern:
            continue
        
        # Try to compile the pattern
        try:
            fnmatch.translate(pattern)
        except Exception as e:
            warnings.append(f"Line {line_num}: Invalid pattern '{pattern}' - {e}")

if warnings:
    print("WARNING: Issues found in allowlist:", file=sys.stderr)
    for w in warnings:
        print(f"  {w}", file=sys.stderr)
PY
}

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
CONFIG_FILE="$REPO_ROOT/patterns.yml"
[[ "$DRY_RUN" != "1" ]] && mkdir -p "$REPORT_DIR"

# Load configuration from patterns.yml if it exists
if [[ -f "$CONFIG_FILE" ]]; then
  log_verbose "Loading configuration from $CONFIG_FILE"
  load_config "$CONFIG_FILE"
  
  # Apply loaded patterns (variables are set directly by load_config now)
  if [[ "$DEFAULT_GREP_PATTERNS" != "(api[_-]?key|secret|token|passwd|password|private[_-]?key|BEGIN (RSA|OPENSSH) PRIVATE KEY)" ]]; then
    log_verbose "Loaded custom grep patterns from config"
  fi
  
  if [[ "$DEFAULT_FILETYPE_PATTERNS" != "\.env|\.pem|\.p12|\.pfx|\.key|\.kdb|\.keystore" ]]; then
    log_verbose "Loaded custom filetype patterns from config"
  fi
fi

# Initialize allowlist if requested
if [[ "$INIT_ALLOWLIST" == "1" ]] && [[ ! -f "$ALLOW_FILE" ]]; then
  cat >"$ALLOW_FILE" <<'EOF'
# .secretcheck_allowed
#
# Glob patterns (fnmatch), used as a WHITELIST for secretcheck.sh.
# Any finding that originates from a matching path is treated as allowed.
# Use this ONLY for known false positives (e.g., docs/examples, test fixtures),
# never for real secrets.
#
# You can add inline comments after patterns:
#   path/to/file.txt  # This is a test fixture
#
# Examples:
# docs/examples/keys.txt
# test/fixtures/**
# **/.env.example
EOF
  log_info "Created allowlist template: $ALLOW_FILE"
  log_info ""
  exit 0
fi

# Display configuration
if [[ "$DRY_RUN" == "1" ]]; then
  echo "🔍 DRY RUN MODE - No tools will be executed"
  echo ""
fi

log_info "SecretCheck v$VERSION"
log_info "Repo: $REPO_ROOT"
log_info "Reports: $REPORT_DIR"
[[ "$FAIL_ALL" == "1" ]] && log_info "Mode: FAIL-ALL (non-interactive)"
[[ "$DRY_RUN" == "1" ]] && log_info "Mode: DRY-RUN (preview only)"
[[ "$VERBOSE" == "1" ]] && log_info "Verbose: ON"
[[ "$QUIET" == "1" ]] && log_info "Quiet: ON"
[[ "$PRINT_ALLOWLISTED" == "1" ]] && log_info "Allowlist reporting: ON"

if [[ -f "$ALLOW_FILE" ]]; then
  log_info "Allowlist: $ALLOW_FILE (re-read each step run)"
else
  log_info "Allowlist: (none) → create .secretcheck_allowed or run with --init-allowlist"
fi

if [[ -f "$CONFIG_FILE" ]]; then
  log_info "Config: $CONFIG_FILE"
fi

# Check if we have exclude patterns (safe for set -u)
EXCLUDE_COUNT="${#EXCLUDE_PATTERNS[@]}"
if [[ "$EXCLUDE_COUNT" -gt 0 ]]; then
  log_info "Exclude patterns: $EXCLUDE_COUNT pattern(s)"
  for pattern in "${EXCLUDE_PATTERNS[@]}"; do
    log_verbose "  - $pattern"
  done
fi

log_info ""

# Check dependencies
check_dependencies() {
  local missing=0
  
  if ! need_cmd gitleaks; then
    echo -e "${RED}Missing: gitleaks${NC}"
    missing=1
  else
    [[ "${CHECK_DEPS:-0}" == "1" ]] && echo -e "${GREEN}Found: gitleaks${NC}"
  fi
  
  if [[ "$SKIP_TRUFFLEHOG" != "1" ]] && ! need_cmd trufflehog; then
    echo -e "${RED}Missing: trufflehog (set SKIP_TRUFFLEHOG=1 to skip)${NC}"
    missing=1
  else
    [[ "${CHECK_DEPS:-0}" == "1" ]] && [[ "$SKIP_TRUFFLEHOG" != "1" ]] && echo -e "${GREEN}Found: trufflehog${NC}"
  fi
  
  if ! check_python_version; then
    missing=1
  else
    [[ "${CHECK_DEPS:-0}" == "1" ]] && echo -e "${GREEN}Found: python3${NC}"
  fi

  if [[ "$missing" == "1" || "${CHECK_DEPS:-0}" == "1" ]]; then
    echo
    echo "Installation options:"
    if [[ "$(uname)" == "Darwin" ]]; then
      echo "  brew install gitleaks"
      echo "  pipx install trufflehog"
    elif [[ -f /etc/debian_version ]]; then
      echo "  (See README for Linux install instructions)"
      echo "  wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz && ..."
      echo "  pipx install trufflehog"
    else
      echo "  - gitleaks: https://github.com/gitleaks/gitleaks"
      echo "  - trufflehog: pipx install trufflehog"
    fi
    
    if [[ "$missing" == "1" ]]; then
      exit 2
    else
      exit 0
    fi
  fi
}

check_dependencies

# Handle self-update
if [[ "${UPDATE_MODE:-0}" == "1" ]]; then
  self_update
fi

# Check git state
check_git_state

# Handle hook installation
if [[ "${INSTALL_HOOK:-0}" == "1" ]]; then
  HOOK_FILE=".git/hooks/pre-commit"
  if [[ -f "$HOOK_FILE" ]]; then
    read -r -p "Hook already exists at $HOOK_FILE. Overwrite? [y/N] " ans
    if [[ ! "$ans" =~ ^[Yy]$ ]]; then
      log_info "Aborting hook installation."
      exit 0
    fi
  else
    read -r -p "Install pre-commit hook to $HOOK_FILE? [y/N] " ans
    if [[ ! "$ans" =~ ^[Yy]$ ]]; then
      log_info "Aborting hook installation."
      exit 0
    fi
  fi
  
  log_info "Installing pre-commit hook..."
  cat >"$HOOK_FILE" <<'EOF'
#!/usr/bin/env bash
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)
if [ -z "$STAGED_FILES" ]; then exit 0; fi

# Create temporary allowlist for staged files
TEMP_ALLOW=$(mktemp)
trap "rm -f $TEMP_ALLOW" EXIT
[ -f .secretcheck_allowed ] && cat .secretcheck_allowed > "$TEMP_ALLOW"

# Allowlist all non-staged files
git ls-files | while read -r file; do
    if ! echo "$STAGED_FILES" | grep -q "^$file$"; then
        echo "$file" >> "$TEMP_ALLOW"
    fi
done

ALLOW_FILE="$TEMP_ALLOW" secretcheck.sh --fail-all
EOF
  chmod +x "$HOOK_FILE"
  log_info "${GREEN}✔ Hook installed successfully to $HOOK_FILE${NC}"
  exit 0
fi

# Validate allowlist
validate_allowlist "$ALLOW_FILE"

# Exit early if dry-run
if [[ "$DRY_RUN" == "1" ]]; then
  echo "Checks that would be performed:"
  echo "  1. gitleaks (full history)"
  [[ "$SKIP_TRUFFLEHOG" != "1" ]] && echo "  2. trufflehog (git history)"
  if [[ "$RUN_BONUS" == "1" ]]; then
    echo "  3. bonus grep (working tree patterns)"
    echo "  4. bonus filetype check (risky extensions in history)"
  fi
  echo
  echo "Dry run complete. Use without --dry-run to actually run checks."
  exit 0
fi

suggest_allowlist() {
  local paths_file="$1"
  [[ -s "$paths_file" ]] || return 0

  echo
  echo "Suggested .secretcheck_allowed entries (review before using):"

  python3 - "$paths_file" "$MAX_ALLOWLIST_SUGGESTIONS" <<'PY'
import os, sys
p=sys.argv[1]
max_sugg=int(sys.argv[2])
paths=[ln.strip() for ln in open(p,'r',encoding='utf-8',errors='ignore') if ln.strip()]
if not paths:
    sys.exit(0)

uniq=[]
seen=set()
for x in paths:
    if x not in seen:
        seen.add(x); uniq.append(x)
uniq=uniq[:max_sugg]

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

# Consolidated allowlist filtering function
# Usage: filter_allowlisted_paths <input_file> <output_file>
# Reads paths from input_file, filters out allowlisted and excluded ones, writes to output_file
filter_allowlisted_paths() {
  local input_file="$1"
  local output_file="$2"
  
  # Convert exclude patterns array to newline-separated string
  local exclude_patterns_str=""
  local exclude_count="${#EXCLUDE_PATTERNS[@]}"
  if [[ "$exclude_count" -gt 0 ]]; then
    for pattern in "${EXCLUDE_PATTERNS[@]}"; do
      exclude_patterns_str+="$pattern"$'\n'
    done
  fi
  
  python3 - "$input_file" "$ALLOW_FILE" "$REPORT_DIR" "$exclude_patterns_str" >"$output_file" <<'PY'
import sys, os
allfile, allow, report_dir, exclude_patterns_str = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
lines=[l.strip() for l in open(allfile,'r',encoding='utf-8',errors='ignore') if l.strip()]

# Parse exclude patterns
exclude_patterns = [p.strip() for p in exclude_patterns_str.strip().split('\n') if p.strip()]

def excluded(path: str) -> bool:
    """Check if path matches any exclude pattern"""
    if not exclude_patterns:
        return False
    import fnmatch
    for pat in exclude_patterns:
        if fnmatch.fnmatch(path, pat):
            return True
    return False

def allowlisted(path: str) -> bool:
    if report_dir:
        rd = report_dir.rstrip(os.sep)
        if path == rd or path.startswith(rd + os.sep): return True
    if not allow or not os.path.isfile(allow): return False
    import fnmatch
    with open(allow, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            # Support inline comments: split on # and take first part
            if '#' in line:
                parts = line.split('#', 1)
                pat = parts[0].strip()
            else:
                pat = line.strip()
            
            if not pat or pat.startswith('#'): continue
            if fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(path, pat.rstrip('/') + '/*'):
                return True
    return False

bad=[p for p in lines if not excluded(p) and not allowlisted(p)]
if bad: print('\n'.join(bad), end='')
PY
}


run_until_clean() {
  local name="$1"
  local runner="$2"
  local raw_log="$3"
  local paths_all="$4"
  local paths_bad="$5"
  local warning_msg="${6:-}"

  while true; do
    log_info "==> $name"
    log_info ""

    # Allowlist is re-read each run.
    if [[ "$DRY_RUN" == "1" ]]; then
      log_info "DRY-RUN: Would run $name"
      return 0
    fi

    log_progress "Running $name..."
    set +e
    "$runner" >"$raw_log" 2>&1
    tool_has_findings_rc=$?
    set -e
    log_progress_done

    : > "$paths_all"
    : > "$paths_bad"
    [[ -f "$paths_all.tmp" ]] && cat "$paths_all.tmp" > "$paths_all" && rm -f "$paths_all.tmp"
    [[ -f "$paths_bad.tmp" ]] && cat "$paths_bad.tmp" > "$paths_bad" && rm -f "$paths_bad.tmp"

    if [[ $tool_has_findings_rc -eq 0 ]]; then
      log_info "PASS: $name"
      log_info ""
      return 0
    fi

    if [[ ! -s "$paths_bad" ]]; then
      log_info "PASS: $name (findings exist, but all are allowlisted)"
      if [[ "$PRINT_ALLOWLISTED" == "1" ]] && [[ -s "$paths_all" ]]; then
        log_info "---- allowlisted paths (seen by tool): $paths_all ----"
        cat "$paths_all" || true
        log_info "-----------------------------------------------------"
      fi
      log_info ""
      return 0
    fi

    log_info "FAIL: $name (non-allowlisted findings)"

    log_info "---- last $LOG_TAIL_LINES lines of raw log: $raw_log ----"
    python3 - "$raw_log" "$LOG_TAIL_LINES" "$MAX_LINE_LENGTH" <<'PY' || true
import sys, os
log_path = sys.argv[1]
tail_lines = int(sys.argv[2])
max_len = int(sys.argv[3])
if not os.path.exists(log_path): sys.exit(0)
try:
    with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
        lines = f.readlines()[-tail_lines:]
    trunc = False
    for line in lines:
        line = line.rstrip('\n')
        if len(line) > max_len:
            print(line[:max_len] + ' [TRUNCATED]')
            trunc = True
        else:
            print(line)
    if trunc:
        print("\n[NOTICE] some long lines were truncated")
except:
    pass
PY
    log_info "-------------------------------------------"
    log_info "${YELLOW}NOTE: Line numbers and file contents above are relative to the specific COMMIT ID reported.${NC}"
    log_info "${YELLOW}Historical findings remain in history even if the current version of the file is clean.${NC}"
    log_info ""

    log_info "---- non-allowlisted paths: $paths_bad ----"
    cat "$paths_bad" || true
    log_info "------------------------------------------"

    if [[ "$PRINT_ALLOWLISTED" == "1" ]] && [[ -s "$paths_all" ]]; then
      log_info "---- allowlisted paths (ignored): ----"
      python3 - "$paths_all" "$paths_bad" <<'PY'
import sys
a=set([l.strip() for l in open(sys.argv[1]) if l.strip()])
b=set([l.strip() for l in open(sys.argv[2]) if l.strip()])
only=sorted(a-b)
print("\n".join(only))
PY
      log_info "--------------------------------------"
    fi

    suggest_allowlist "$paths_bad"

    if [[ -n "$warning_msg" ]]; then
      log_info "$warning_msg"
      log_info ""
    fi

    if [[ "$FAIL_ALL" == "1" ]]; then
      log_info "FAIL-ALL active -> aborting."
      exit 1
    fi

    set +e
    pause_for_user
    pause_rc=$?
    set -e

    if [[ $pause_rc -eq 2 ]]; then
      log_info "SKIPPING: $name (as requested by user)"
      SKIPPED_ANY=1
      log_info ""
      return 0
    fi

    log_info ""
  done
}

# --------------------------------------------------
# Step 1: gitleaks (full history)
# --------------------------------------------------
GITLEAKS_LOG="$REPORT_DIR/gitleaks.log"
GITLEAKS_JSON="$REPORT_DIR/gitleaks.json"
GITLEAKS_ALL="$REPORT_DIR/gitleaks.paths_all.txt"
GITLEAKS_BAD="$REPORT_DIR/gitleaks.paths_bad.txt"

check_gitleaks() {
  local opts="--log-opts=--all"
  if [[ "${FAST_MODE:-0}" == "1" ]]; then
    opts="--log-opts=-1"
    log_info "${YELLOW}FAST MODE: Scanning last commit only${NC}"
  fi

  gitleaks detect --source . $opts --redact --report-format json --report-path "$GITLEAKS_JSON" --verbose > "$GITLEAKS_LOG.tmp_raw" 2>&1 || true

  python3 - "$GITLEAKS_JSON" >"$GITLEAKS_ALL.tmp" 2>/dev/null <<'PY'
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
print('\n'.join(out))
PY

  filter_allowlisted_paths "$GITLEAKS_ALL.tmp" "$GITLEAKS_BAD.tmp"

  python3 - "$GITLEAKS_LOG.tmp_raw" "$GITLEAKS_BAD.tmp" <<'PY'
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
  rm -f "$GITLEAKS_LOG.tmp_raw"

  python3 - "$GITLEAKS_JSON" <<'PY'
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
  local findings_rc=$?

  # Generate SARIF if requested (secondary run)
  if [[ "${SARIF_MODE:-0}" == "1" ]]; then
    local sarif_file="$REPORT_DIR/gitleaks.sarif"
    log_info "${BLUE}Generating SARIF report (secondary run)...${NC}"
    gitleaks detect --source . $opts --redact --report-format sarif --report-path "$sarif_file" >/dev/null 2>&1 || true
    log_info "${GREEN}SARIF report saved to: $sarif_file${NC}"
  fi

  return $findings_rc
}

run_until_clean \
  "gitleaks (full history)" \
  check_gitleaks \
  "$GITLEAKS_LOG" "$GITLEAKS_ALL" "$GITLEAKS_BAD"

# --------------------------------------------------
# Step 2: trufflehog (git history)
# --------------------------------------------------
if [[ "$SKIP_TRUFFLEHOG" != "1" ]]; then
  TRUFFLEHOG_LOG="$REPORT_DIR/trufflehog.log"
  TRUFFLEHOG_JSONL="$REPORT_DIR/trufflehog.jsonl"
  TRUFFLEHOG_ALL="$REPORT_DIR/trufflehog.paths_all.txt"
  TRUFFLEHOG_BAD="$REPORT_DIR/trufflehog.paths_bad.txt"


check_trufflehog() {
  if [[ "${FAST_MODE:-0}" == "1" ]]; then
    log_info "${YELLOW}FAST MODE: Skipping TruffleHog deep scan (not supported in fast mode)${NC}"
    return 0
  fi
  trufflehog git file://"$REPO_ROOT" --only-verified=false --json >"$TRUFFLEHOG_JSONL" 2>/dev/null || true

  python3 - "$TRUFFLEHOG_JSONL" >"$TRUFFLEHOG_ALL.tmp" <<'PY'
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
print('\n'.join(out))
PY

  filter_allowlisted_paths "$TRUFFLEHOG_ALL.tmp" "$TRUFFLEHOG_BAD.tmp"

  python3 - "$TRUFFLEHOG_JSONL" "$TRUFFLEHOG_BAD.tmp" <<'PY'
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
            print(f"Detector:    {o.get('DetectorName') or 'Unknown'}")
            print(f"Verified:    {o.get('Verified')}")
            print('Commit:      ' + str(git.get('Commit') or ''))
            print()
PY

  python3 - "$TRUFFLEHOG_JSONL" <<'PY'
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
}

  run_until_clean \
    "trufflehog (git history)" \
    check_trufflehog \
    "$TRUFFLEHOG_LOG" "$TRUFFLEHOG_ALL" "$TRUFFLEHOG_BAD"
else
  echo "SKIP: trufflehog"
  echo
fi

# --------------------------------------------------
# Bonus checks
#
# These checks use patterns from patterns.yml if available, otherwise defaults.
# Customize patterns in patterns.yml for your project-specific needs.
# --------------------------------------------------
if [[ "$RUN_BONUS" != "1" ]]; then
  log_info "SKIP: bonus checks (opt-in via --bonus or RUN_BONUS=1)"
  log_info ""
else
  # Step 3: keyword grep in working tree
  BONUS_GREP_LOG="$REPORT_DIR/bonus_grep.log"
  BONUS_GREP_ALL="$REPORT_DIR/bonus_grep.paths_all.txt"
  BONUS_GREP_BAD="$REPORT_DIR/bonus_grep.paths_bad.txt"

check_bonus_grep() {
    log_verbose "Using grep patterns: $DEFAULT_GREP_PATTERNS"
    set +e
    git -c core.quotepath=false grep -lEi "$DEFAULT_GREP_PATTERNS" >"$BONUS_GREP_LOG.tmp_raw" 2>&1
    rc=$?
    set -e

    python3 - "$BONUS_GREP_LOG.tmp_raw" >"$BONUS_GREP_ALL.tmp" <<'PY'
import sys, os
p=sys.argv[1]
if not os.path.isfile(p):
    sys.exit(0)
paths=[]
for ln in open(p,'r',encoding='utf-8',errors='replace'):
    path=ln.strip()
    if path:
        paths.append(path)
seen=set(); out=[]
for x in paths:
    if x not in seen:
        seen.add(x); out.append(x)
print('\n'.join(out))
PY

    filter_allowlisted_paths "$BONUS_GREP_ALL.tmp" "$BONUS_GREP_BAD.tmp"

    python3 - "$BONUS_GREP_LOG.tmp_raw" "$BONUS_GREP_BAD.tmp" <<'PY'
import sys, os
log, bad_f = sys.argv[1], sys.argv[2]
bad_set = set([l.strip() for l in open(bad_f, encoding='utf-8', errors='replace') if l.strip()]) if os.path.exists(bad_f) else set()
if not os.path.exists(log): sys.exit(0)
with open(log, 'r', encoding='utf-8', errors='replace') as f:
    for line in f:
        path = line.strip()
        if path in bad_set:
            print(path)
PY
    rm -f "$BONUS_GREP_LOG.tmp_raw"

    # Return based on whether there are bad paths after filtering, not git grep's exit code
    if [[ -s "$BONUS_GREP_BAD.tmp" ]]; then
        return 1  # Has findings
    else
        return 0  # Clean or all allowlisted
    fi
}

  run_until_clean \
    "bonus grep (working tree obvious patterns)" \
    check_bonus_grep \
    "$BONUS_GREP_LOG" "$BONUS_GREP_ALL" "$BONUS_GREP_BAD" \
    "NOTE: Bonus checks often produce many false positives. They can be helpful but require manual review."

  # Step 4: risky filetypes ever in history
  BONUS_TYPES_LOG="$REPORT_DIR/bonus_history_filetypes.log"
  BONUS_TYPES_ALL="$REPORT_DIR/bonus_history_filetypes.paths_all.txt"
  BONUS_TYPES_BAD="$REPORT_DIR/bonus_history_filetypes.paths_bad.txt"

check_bonus_filetypes() {
    log_verbose "Using filetype patterns: $DEFAULT_FILETYPE_PATTERNS"
    set +e
    git -c core.quotepath=false log --all --name-only --pretty=format: | grep -nEi "$DEFAULT_FILETYPE_PATTERNS" >"$BONUS_TYPES_LOG.tmp_raw" 2>&1
    rc=$?
    set -e

    python3 - "$BONUS_TYPES_LOG.tmp_raw" >"$BONUS_TYPES_ALL.tmp" <<'PY'
import sys, os
p=sys.argv[1]
if not os.path.isfile(p):
    sys.exit(0)
paths=[]
for ln in open(p,'r',encoding='utf-8',errors='replace'):
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
print('\n'.join(out))
PY

    filter_allowlisted_paths "$BONUS_TYPES_ALL.tmp" "$BONUS_TYPES_BAD.tmp"

    # Return based on whether there are bad paths after filtering
    if [[ -s "$BONUS_TYPES_BAD.tmp" ]]; then
        return 1  # Has findings
    else
        return 0  # Clean or all allowlisted
    fi
}

  run_until_clean \
    "bonus history filetype check (.env/.pem/.p12/...)" \
    check_bonus_filetypes \
    "$BONUS_TYPES_LOG" "$BONUS_TYPES_ALL" "$BONUS_TYPES_BAD" \
    "NOTE: Bonus checks often produce many false positives. They can be helpful but require manual review."
fi

if [[ "$SKIPPED_ANY" == "1" ]]; then
  log_info "⚠️  SOME CHECKS HAVE FAILED (see above)"
  log_info "Reports saved in: $REPORT_DIR"
  exit 1
else
  log_info "✅ ALL CHECKS CLEAN (or allowlisted)"
  log_info "Reports saved in: $REPORT_DIR"
fi
