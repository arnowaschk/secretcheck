#!/bin/bash
set -u

# Path to the script under test
SC_PATH="$(pwd)/secretcheck.sh"
TEST_DIR="/tmp/secretcheck_test_env"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "Starting secretcheck integration tests..."

cleanup() {
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# 0. Test Operational Error (Run outside git repo)
echo "Test 0: Operational Error (non-git repo)"
mkdir -p "$TEST_DIR/no_git"
cd "$TEST_DIR/no_git"
"$SC_PATH" --fail-all >/dev/null 2>&1
rc=$?
if [[ $rc -ne 2 ]]; then
    echo -e "${RED}FAIL: Expected exit 2 for non-git repo, got $rc${NC}"
    exit 1
fi
echo -e "${GREEN}PASS: Operational error caught correctly${NC}"

# Setup test repo
echo "Preparing test repo in $TEST_DIR..."
mkdir -p "$TEST_DIR/repo"
cd "$TEST_DIR/repo"
git init -q
git config user.email "test@example.com"
git config user.name "Test User"

# 1. Test Clean Repo
echo "Test 1: Clean repo"
"$SC_PATH" --fail-all
rc=$?
if [[ $rc -ne 0 ]]; then
    echo -e "${RED}FAIL: Clean repo should return 0, got $rc${NC}"
    exit 1
fi
echo -e "${GREEN}PASS: Clean repo${NC}"

# 2. Test Finding Detection (Gitleaks)
echo "Test 2: Gitleaks finding"
echo "aws_access_key_id=AKIA1234567890123456" > aws_key.txt
git add aws_key.txt
git commit -m "add key" -q
"$SC_PATH" --fail-all >/dev/null 2>&1
rc=$?
if [[ $rc -ne 1 ]]; then
    echo -e "${RED}FAIL: Expected exit 1 for secret finding, got $rc${NC}"
    exit 1
fi
echo -e "${GREEN}PASS: Finding detected${NC}"

# 3. Test Allowlist
echo "Test 3: Allowlist"
echo "aws_key.txt" > .secretcheck_allowed
"$SC_PATH" --fail-all
rc=$?
if [[ $rc -ne 0 ]]; then
    echo -e "${RED}FAIL: Allowlist should result in exit 0, got $rc${NC}"
    exit 1
fi
echo -e "${GREEN}PASS: Allowlist works${NC}"

# 4. Test Bonus Check & Log Safety
echo "Test 4: Bonus check ('your_own_secret') & Log safety"
echo "my_val=your_own_secret" > custom.txt
git add custom.txt
"$SC_PATH" --fail-all --bonus >/dev/null 2>&1
rc=$?
if [[ $rc -ne 1 ]]; then
    echo -e "${RED}FAIL: Expected exit 1 for bonus finding, got $rc${NC}"
    exit 1
fi

# Verify log safety (should not contain the secret string)
if [[ -f .secretcheck/bonus_grep.log.tmp_raw ]]; then
    if grep -q "your_own_secret" .secretcheck/bonus_grep.log.tmp_raw 2>/dev/null; then
        echo -e "${RED}FAIL: Secret content found in log!${NC}"
        exit 1
    fi
fi
echo "PASS: Bonus check detected and log is safe (filenames only)"

# 5. Test Bonus Filetype
echo "Test 5: Bonus filetype (.env)"
echo "SECRET_KEY=123" > .env
git add .env
git commit -m "add risky file" -q
"$SC_PATH" --fail-all --bonus >/dev/null 2>&1
rc=$?
if [[ $rc -ne 1 ]]; then
    echo -e "${RED}FAIL: Expected exit 1 for bonus filetype (.env), got $rc${NC}"
    exit 1
fi
echo -e "${GREEN}PASS: Bonus filetype found (.env)${NC}"

echo -e "\n${GREEN}ALL INTEGRATION TESTS PASSED SUCCESSFULLY${NC}"
