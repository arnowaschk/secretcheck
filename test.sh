#!/bin/bash
set -u

# Enhanced test suite for secretcheck
# Tests basic functionality plus edge cases

# Path to the script under test
SC_PATH="$(pwd)/secretcheck.sh"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "Starting secretcheck integration tests..."

# Use mktemp for test directory
TEST_DIR=$(mktemp -d -t secretcheck_test.XXXXXX)

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# Test counter
TESTS_RUN=0
TESTS_PASSED=0

run_test() {
    local test_name="$1"
    TESTS_RUN=$((TESTS_RUN + 1))
    echo -e "${YELLOW}Test $TESTS_RUN: $test_name${NC}"
}

pass_test() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "${GREEN}PASS${NC}"
    echo
}

fail_test() {
    local expected="$1"
    local got="$2"
    echo -e "${RED}FAIL: Expected exit $expected, got $got${NC}"
    exit 1
}

# ============================================================================
# Test 0: Operational Error (Run outside git repo)
# ============================================================================
run_test "Operational Error (non-git repo)"
mkdir -p "$TEST_DIR/no_git"
cd "$TEST_DIR/no_git"
"$SC_PATH" --fail-all >/dev/null 2>&1
rc=$?
if [[ $rc -ne 2 ]]; then
    fail_test 2 $rc
fi
pass_test

# ============================================================================
# Setup test repo
# ============================================================================
echo "Preparing test repo in $TEST_DIR..."
mkdir -p "$TEST_DIR/repo"
cd "$TEST_DIR/repo"
git init -q
git config user.email "test@example.com"
git config user.name "Test User"

# ============================================================================
# Test 1: Clean Repo
# ============================================================================
run_test "Clean repo"
"$SC_PATH" --fail-all
rc=$?
if [[ $rc -ne 0 ]]; then
    fail_test 0 $rc
fi
pass_test

# ============================================================================
# Test 2: Finding Detection (Gitleaks)
# ============================================================================
run_test "Gitleaks finding"
echo "aws_access_key_id=AKIA1234567890123456" > aws_key.txt
git add aws_key.txt
git commit -m "add key" -q
"$SC_PATH" --fail-all >/dev/null 2>&1
rc=$?
if [[ $rc -ne 1 ]]; then
    fail_test 1 $rc
fi
pass_test

# ============================================================================
# Test 3: Allowlist
# ============================================================================
run_test "Allowlist"
echo "aws_key.txt" > .secretcheck_allowed
"$SC_PATH" --fail-all
rc=$?
if [[ $rc -ne 0 ]]; then
    fail_test 0 $rc
fi
pass_test

# ============================================================================
# Test 4: Inline Comments in Allowlist
# ============================================================================
run_test "Inline comments in allowlist"
echo "custom.txt  # This is a test file" >> .secretcheck_allowed
echo "my_val=your_own_secret" > custom.txt
git add custom.txt
git commit -m "add custom" -q
"$SC_PATH" --fail-all --bonus >/dev/null 2>&1
rc=$?
if [[ $rc -ne 0 ]]; then
    fail_test 0 $rc
fi
pass_test

# ============================================================================
# Test 5: Bonus Check & Log Safety
# ============================================================================
run_test "Bonus check ('your_own_secret') & Log safety"
rm .secretcheck_allowed
"$SC_PATH" --fail-all --bonus >/dev/null 2>&1
rc=$?
if [[ $rc -ne 1 ]]; then
    fail_test 1 $rc
fi

# Verify log safety (should not contain the secret string)
if [[ -f .secretcheck/bonus_grep.log.tmp_raw ]]; then
    if grep -q "your_own_secret" .secretcheck/bonus_grep.log.tmp_raw 2>/dev/null; then
        echo -e "${RED}FAIL: Secret content found in log!${NC}"
        exit 1
    fi
fi
pass_test

# ============================================================================
# Test 6: Bonus Filetype
# ============================================================================
run_test "Bonus filetype (.env)"
echo "SECRET_KEY=123" > .env
git add .env
git commit -m "add risky file" -q
"$SC_PATH" --fail-all --bonus >/dev/null 2>&1
rc=$?
if [[ $rc -ne 1 ]]; then
    fail_test 1 $rc
fi
pass_test

# ============================================================================
# Test 7: Exclude Patterns
# ============================================================================
run_test "Exclude patterns"
"$SC_PATH" --fail-all --bonus --exclude "*.env" --exclude "custom.txt" --exclude "aws_key.txt" >/dev/null 2>&1
rc=$?
if [[ $rc -ne 0 ]]; then
    fail_test 0 $rc
fi
pass_test

# ============================================================================
# Test 8: Dry Run Mode
# ============================================================================
run_test "Dry run mode"
rm -rf .secretcheck
"$SC_PATH" --dry-run --bonus >/dev/null 2>&1
rc=$?
if [[ $rc -ne 0 ]]; then
    fail_test 0 $rc
fi
# Verify no reports were created in dry run
if [[ -f .secretcheck/gitleaks.json ]]; then
    echo -e "${RED}FAIL: Reports created in dry-run mode!${NC}"
    exit 1
fi
pass_test

# ============================================================================
# Test 9: Help and Version Flags
# ============================================================================
run_test "Help flag"
"$SC_PATH" --help >/dev/null 2>&1
rc=$?
if [[ $rc -ne 0 ]]; then
    fail_test 0 $rc
fi
pass_test

run_test "Version flag"
"$SC_PATH" --version >/dev/null 2>&1
rc=$?
if [[ $rc -ne 0 ]]; then
    fail_test 0 $rc
fi
pass_test

# ============================================================================
# Test 10: Unicode Filenames
# ============================================================================
run_test "Unicode filename handling"
echo "secret=test123" > "tëst_fïlé.txt"
git add "tëst_fïlé.txt"
git commit -m "add unicode file" -q
echo "aws_key.txt" > .secretcheck_allowed
echo "custom.txt" >> .secretcheck_allowed
echo ".env" >> .secretcheck_allowed
echo "tëst_fïlé.txt" >> .secretcheck_allowed
"$SC_PATH" --fail-all --bonus >/dev/null 2>&1
rc=$?
if [[ $rc -ne 0 ]]; then
    fail_test 0 $rc
fi
pass_test

# ============================================================================
# Test 11: Custom patterns.yml
# ============================================================================
run_test "Custom patterns.yml"
cat > patterns.yml <<'EOF'
bonus_grep_patterns:
  - "CUSTOM_SECRET"

bonus_filetype_patterns:
  - "\\.secret"

exclude_patterns:
  - "*.env"

settings:
  log_tail_lines: 50
  max_line_length: 200
EOF

echo "CUSTOM_SECRET=abc123" > test_custom.txt
git add test_custom.txt
git commit -m "add custom secret" -q
"$SC_PATH" --fail-all --bonus >/dev/null 2>&1
rc=$?
if [[ $rc -ne 1 ]]; then
    fail_test 1 $rc
fi
pass_test

# ============================================================================
# Test 12: Empty Repository
# ============================================================================
run_test "Empty repository"
cd "$TEST_DIR"
mkdir -p empty_repo
cd empty_repo
git init -q
git config user.email "test@example.com"
git config user.name "Test User"
"$SC_PATH" --fail-all >/dev/null 2>&1
rc=$?
if [[ $rc -ne 0 ]]; then
    fail_test 0 $rc
fi
pass_test

# ============================================================================
# Test 13: Detached HEAD State
# ============================================================================
run_test "Detached HEAD state"
cd "$TEST_DIR/repo"
rm -f .secretcheck_allowed
git checkout HEAD~1 -q 2>/dev/null || git checkout HEAD -q
"$SC_PATH" --fail-all --no-color >/dev/null 2>&1
rc=$?
# Should still work, just with a warning
if [[ $rc -ne 1 ]]; then  # Still has findings from earlier tests
    fail_test 1 $rc
fi
git checkout main -q 2>/dev/null || git checkout master -q 2>/dev/null || true
pass_test

# ============================================================================
# Test 14: --no-color flag
# ============================================================================
run_test "--no-color flag"
# Run and check that no ANSI escape codes are in the output
output=$("$SC_PATH" --no-color --help 2>&1)
if echo "$output" | grep -q $'\e'; then
    echo -e "${RED}FAIL: ANSI escape codes found in output with --no-color${NC}"
    exit 1
fi
pass_test

# ============================================================================
# Test 15: --check-deps
# ============================================================================
run_test "--check-deps flag"
"$SC_PATH" --check-deps >/dev/null 2>&1
rc=$?
if [[ $rc -ne 0 ]]; then
    fail_test 0 $rc
fi
pass_test

# ============================================================================
# Test 16: --fast mode
# ============================================================================
run_test "--fast mode (incremental scan)"
# Verify it logs FAST MODE in verbose
# log_info now writes to stderr, so we must capture it
output=$("$SC_PATH" --fast --verbose --fail-all 2>&1)
if ! echo "$output" | grep -q "FAST MODE"; then
    echo -e "${RED}FAIL: FAST MODE marker not found in output${NC}"
    exit 1
fi
pass_test

# ============================================================================
# Test 17: --sarif report
# ============================================================================
run_test "--sarif report generation"
rm -rf .secretcheck
"$SC_PATH" --sarif --fail-all >/dev/null 2>&1
if [[ ! -f .secretcheck/gitleaks.sarif ]]; then
    echo -e "${RED}FAIL: SARIF report was not created${NC}"
    exit 1
fi
pass_test

# ============================================================================
# Test 18: --init-allowlist
# ============================================================================
run_test "--init-allowlist flag"
rm -f .secretcheck_allowed
"$SC_PATH" --init-allowlist >/dev/null 2>&1
if [[ ! -f .secretcheck_allowed ]]; then
    echo -e "${RED}FAIL: .secretcheck_allowed was not created${NC}"
    exit 1
fi
if ! grep -q "fnmatch" .secretcheck_allowed; then
    echo -e "${RED}FAIL: Template content not found in .secretcheck_allowed${NC}"
    exit 1
fi
pass_test

# ============================================================================
# Test 19: --quiet mode
# ============================================================================
run_test "--quiet mode"
# Clear findings or use a clean repo
cd "$TEST_DIR"
mkdir -p quiet_test
cd quiet_test
git init -q
# Use a file for capture to avoid potential subshell hang issues
TMP_OUT=$(mktemp)
echo "DEBUG: Running quiet test..."
"$SC_PATH" --quiet --fail-all >"$TMP_OUT" 2>&1
rc=$?
output=$(cat "$TMP_OUT")
rm -f "$TMP_OUT"
if [[ -n "$output" ]]; then
    echo -e "${RED}FAIL: Quiet mode produced output: $output${NC}"
    exit 1
fi
if [[ $rc -ne 0 ]]; then
    fail_test 0 $rc
fi
pass_test

# ============================================================================
# Test 20: --verbose mode
# ============================================================================
run_test "--verbose mode"
output=$("$SC_PATH" --verbose --fail-all 2>&1)
if ! echo "$output" | grep -q "VERBOSE"; then
    echo -e "${RED}FAIL: Verbose output missing [VERBOSE] markers${NC}"
    exit 1
fi
pass_test

# ============================================================================
# Test 21: --install-hook (n confirmation)
# ============================================================================
run_test "--install-hook (decline)"
rm -f .git/hooks/pre-commit
echo "n" | "$SC_PATH" --install-hook >/dev/null 2>&1
if [[ -f .git/hooks/pre-commit ]]; then
    echo -e "${RED}FAIL: Hook created despite declining${NC}"
    exit 1
fi
pass_test

# ============================================================================
# Test 22: --install-hook (y confirmation)
# ============================================================================
run_test "--install-hook (accept)"
echo "y" | "$SC_PATH" --install-hook >/dev/null 2>&1
if [[ ! -f .git/hooks/pre-commit ]]; then
    echo -e "${RED}FAIL: Hook not created after accepting${NC}"
    exit 1
fi
if [[ ! -x .git/hooks/pre-commit ]]; then
    echo -e "${RED}FAIL: Hook is not executable${NC}"
    exit 1
fi
pass_test

# ============================================================================
# Test 23: --update (check only)
# ============================================================================
run_test "--update flag (dry run/check only)"
# We can't easily test actual download without network, but we check if it triggers
echo "n" | "$SC_PATH" --update 2>&1 | grep -q "Checking for updates"
rc=$?
if [[ $rc -ne 0 ]]; then
    echo -e "${RED}FAIL: --update didn't trigger update check${NC}"
    exit 1
fi
pass_test

# ============================================================================
# Summary
# ============================================================================
echo
echo "========================================"
echo -e "${GREEN}ALL TESTS PASSED: $TESTS_PASSED/$TESTS_RUN${NC}"
echo "========================================"
