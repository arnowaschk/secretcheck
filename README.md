# SecretCheck

```
   ____                     _    ____ _               _    
  / ___|  ___  ___ _ __ ___| |_ / ___| |__   ___  ___| | __
  \___ \ / _ \/ __| '__/ _ \ __| |   | '_ \ / _ \/ __| |/ /
   ___) |  __/ (__| | |  __/ |_| |___| | | |  __/ (__|   < 
  |____/ \___|\___|_|  \___|\__|\____|_| |_|\___|\___|_|\_\
```

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/version-1.0.2-blue.svg)](https://github.com/arnowaschk/secretcheck/releases)

Let's be honest: we've all been there. It's late, the coffee is cold, and you just want to push that one "tiny" fix. Suddenly, your AWS keys or that super-secret database password are out in the wild, waving hello to the entire internet. Everyone knows that this must not happen, but it does. People are rushing, they have dozens of small projects in parallel, or they overlook when their AI is doing sloppy things.

Humans are wonderfully fallible, AI still is too, but Git history is forever. **SecretCheck** is here to be your last line of defense—that slightly paranoid friend who double-checks your pockets before you leave the house.

Not a replacement for proper security practices, but a helpful tool to catch mistakes.
Not a breaking new invention, just a tiny wrapper around gitleaks and trufflehog with some extra features.
Put it in your loop or CI pipeline or under your pillow.

## What is this?

SecretCheck is a wrapper script that orchestrates several heavy-hitters in the secret-detection world (`gitleaks`, `trufflehog`) along with some custom "bonus" checks. The latter are optional (via --bonus) and will easily show false positives, but might still catch something the former tools did not find.
It's designed to be interactive, helpful, and easily specialized via an allowlist and configuration file.

## Installation

### Prerequisites

SecretCheck requires:

- **Git** (obviously)
- **Python 3.6+**
- **gitleaks**
- **trufflehog** (optional, can be skipped with `SKIP_TRUFFLEHOG=1`)

### Linux (Debian/Ubuntu)

```bash
# Install gitleaks
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz
tar -xzf gitleaks_8.18.1_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/
rm gitleaks_8.18.1_linux_x64.tar.gz

# Install trufflehog
pipx install trufflehog
# or: pip3 install --user trufflehog

# Install secretcheck
curl -sSL https://raw.githubusercontent.com/arnowaschk/secretcheck/main/secretcheck.sh -o secretcheck.sh
chmod +x secretcheck.sh
sudo mv secretcheck.sh /usr/local/bin/secretcheck
```

### macOS

```bash
# Using Homebrew
brew install gitleaks
pipx install trufflehog

# Install secretcheck
curl -sSL https://raw.githubusercontent.com/arnowaschk/secretcheck/main/secretcheck.sh -o secretcheck.sh
chmod +x secretcheck.sh
sudo mv secretcheck.sh /usr/local/bin/secretcheck
```

### Windows

```powershell
# Using winget (Windows Package Manager)
winget install gitleaks.gitleaks

# Install Python and pipx first if not already installed
winget install Python.Python.3.12
python -m pip install --user pipx
python -m pipx ensurepath
pipx install trufflehog

# Download secretcheck.sh
# Run via Git Bash or WSL
```

### Manual Installation

Download `secretcheck.sh` and place it in your `PATH`:

```bash
curl -sSL https://raw.githubusercontent.com/arnowaschk/secretcheck/main/secretcheck.sh -o secretcheck.sh
chmod +x secretcheck.sh
# Move to a directory in your PATH, e.g.:
sudo mv secretcheck.sh /usr/local/bin/secretcheck
```

## Quick Start

Just run it from your repo's root folder:

```bash
secretcheck.sh
```

### Options

- `--help`: Show comprehensive help message
- `--version`: Show version information
- `--bonus`: Opt-in to the "Bonus checks". Templates for custom rules
- `--fail-all`: Perfect for CI/CD. Fails and exits at the first sign of trouble
- `--dry-run`: Preview what would be checked without actually running tools
- `--fast`: Fast scan (recent files only, skips deep history scans)
- `--exclude PATTERN`: Exclude paths matching glob pattern (multiple allowed)
- `--install-hook`: Automated installation of the git pre-commit hook
- `--check-deps`: Check if required dependencies are installed correctly
- `--update`: Check for and install script updates from GitHub
- `--sarif`: Generate a SARIF report for security tab integration
- `--verbose`: Show detailed progress information
- `--quiet`: Minimize output (errors only)
- `--no-color`: Disable colorized output
- `--print-allowlisted`: Show findings even if they are on your allowlist
- `--init-allowlist`: Creates a template `.secretcheck_allowed` file

### Environment Variables

- `RUN_BONUS=1`: Same as the `--bonus` flag
- `FAIL_ALL=1`: Same as the `--fail-all` flag
- `REPORT_DIR`: Where to store the raw logs (defaults to `.secretcheck`)
- `PRINT_ALLOWLISTED=1`: Show findings even if they are already on your allowlist
- `SKIP_TRUFFLEHOG=1`: Skip trufflehog scan

## Configuration

### patterns.yml

Create a `patterns.yml` file in your repo root to customize search patterns:

```yaml
bonus_grep_patterns:
  - "api[_-]?key"
  - "secret"
  - "STRIPE_SECRET"
  - "DATABASE_URL"

bonus_filetype_patterns:
  - "\\.env"
  - "\\.pem"
  - "\\.credentials"

exclude_patterns:
  - "vendor/**"
  - "node_modules/**"

settings:
  log_tail_lines: 100
  max_line_length: 400
  max_allowlist_suggestions: 30
```

The script uses comprehensive built-in defaults, so this file is entirely optional.

### The Allowlist (.secretcheck_allowed)

Create a file named `.secretcheck_allowed` in your repo root. You can use glob patterns (fnmatch, like `tests/data/**` or `config/dummy_keys.json`) to tell SecretCheck: "I know about this file(s), I know for sure it's not a real danger, stop yelling at me."

Supports inline comments:

```
# Documentation examples
docs/examples/**

# Test fixtures with dummy data
test/fixtures/**  # These are not real secrets

# Specific files
config/dummy_keys.json  # Example keys from official docs
```

## CI/CD Integration

### GitHub Actions

A full history scan is recommended to catch secrets in previous commits.

```yaml
name: Secret Check

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  secretcheck:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0
    
    - name: Install dependencies
      run: |
        wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz
        tar -xzf gitleaks_8.18.1_linux_x64.tar.gz
        sudo mv gitleaks /usr/local/bin/
        pip install trufflehog
    
    - name: Run SecretCheck
      run: |
        curl -sSL https://raw.githubusercontent.com/arnowaschk/secretcheck/main/secretcheck.sh -o secretcheck.sh
        chmod +x secretcheck.sh
        ./secretcheck.sh --fail-all --bonus
```

### GitLab CI

```yaml
secretcheck:
  stage: test
  image: ubuntu:latest
  before_script:
    - apt-get update -qq && apt-get install -y wget python3 python3-pip git
    - wget -q https://github.com/gitleaks/gitleaks/releases/download/v8.18.1/gitleaks_8.18.1_linux_x64.tar.gz
    - tar -xzf gitleaks_8.18.1_linux_x64.tar.gz
    - mv gitleaks /usr/local/bin/
    - pip3 install trufflehog
  script:
    - wget -q https://raw.githubusercontent.com/arnowaschk/secretcheck/main/secretcheck.sh
    - chmod +x secretcheck.sh
    - ./secretcheck.sh --fail-all --bonus
```

### Pre-commit Hook

The easiest way to install the pre-commit hook is to run:

```bash
./secretcheck.sh --install-hook
```

This will create or update `.git/hooks/pre-commit` to catch secrets before they are committed. Alternatively, you can create the file manually with the following content:

```bash
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
```

## Troubleshooting

### "Missing: gitleaks" or "Missing: trufflehog"

Install the missing tools using the installation instructions above. If you want to skip trufflehog, set `SKIP_TRUFFLEHOG=1`.

### "Python 3.6 or higher required"

Update your Python installation. SecretCheck requires Python 3.6+ for proper unicode handling and f-string support.

### Findings in binary files or generated code

Add these to your `.secretcheck_allowed` or use `--exclude` patterns:

```bash
./secretcheck.sh --exclude "**/*.min.js" --exclude "dist/**"
```

### Too many false positives in bonus checks

Bonus checks are intentionally broad. Either:

1. Don't use `--bonus` in CI (only use gitleaks + trufflehog)
2. Customize patterns in `patterns.yml` to be more specific
3. Add false positives to `.secretcheck_allowed`

### Large repository takes too long

Consider:

1. Using `--exclude` to skip vendor directories
2. Running without `--bonus` in CI
3. Setting `SKIP_TRUFFLEHOG=1` if you only want gitleaks

### Unicode filename errors

SecretCheck now handles unicode filenames gracefully with `errors='replace'`. If you still see issues, please report them.

## Exit Codes

- `0`: All checks passed (clean or allowlisted)
- `1`: Findings detected (fail-all mode or user skipped checks)
- `2`: Operational error (missing tools, not a git repo, invalid arguments)
- `3`: User aborted (interactive mode)

## Support & Feedback ☕

If SecretCheck just saved you from a frantic API key rotation at 3 AM, maybe it's worth a small karma bonus? I'd be happy about a [digital coffee](https://buymeacoffee.com/arnwas) to help keep the paranoia high and the bugs low.

But honestly? Just **saying hello** or giving some feedback is even better! It's always nice to know that this slightly paranoid tool is actually out there helping someone.

Or found a bug, or have an idea? Open an issue or a PR!

## Contributing

Thanks for helping make SecretCheck better!

### Reporting Bugs & Features

Please open a GitHub issue with clear reproduction steps or a detailed description of your idea.

### Pull Requests

1. Fork and create a feature branch.
2. Ensure `./test.sh` passes.
3. Keep logic human-readable and well-commented.

## Security Policy

If you discover a security vulnerability in SecretCheck itself:

1. **Do NOT** open a public issue.
2. Email: [arno+security@arnow.solutions](mailto:arno+security@arnow.solutions)
3. We'll acknowledge within 48 hours.

## License

MIT License - Copyright (c) 2026 Arno Waschk. See the repository's `LICENSE` file for full text.

## Changelog

### [1.0.2] - 2026-02-22

- **Improved Displaying**: Added commit-relative line number clarification to reports to reduce confusion for findings in history.
- **Improved Test Suite**: Expanded test coverage to 25 comprehensive integration tests.

### [1.0.1] - 2026-02-15

- **Simplified Repository**: Consolidated documentation into `README.md` and embedded defaults into the script.
- **Enhanced UX**: Added colorized output, automated hook installation (`--install-hook`), and dependency checking (`--check-deps`).
- **New Modes**: Added `--fast` for incremental scans, `--update` for self-upgrading, and `--sarif` for security tab reports.
- **Hardened Logic**: Improved argument parsing, dry-run safety, and secure configuration loading (no `eval`).
- **Robustness**: Better unicode filename handling and detached HEAD state detection.
- **Test Suite**: Enhanced with 15 comprehensive integration tests.

### [1.0.0] - 2026-02-02

- Initial release with Gitleaks and Trufflehog integration.
