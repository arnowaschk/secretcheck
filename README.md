# SecretCheck

Let's be honest: we've all been there. It's late, the coffee is cold, and you just want to push that one "tiny" fix. Suddenly, your AWS keys or that super-secret database password are out in the wild, waving hello to the entire internet.

Humans are wonderfully fallible, but Git history is forever. **SecretCheck** is here to be your last line of defense—that slightly paranoid friend who double-checks your pockets before you leave the house.

Not a replacement for proper security practices, but a helpful tool to catch mistakes.
Not a breaking new invention, just a tiny wrapper around gitleaks and trufflehog with some extra features.
Put it in your loop or CI pipeline or under your pillow.

## What is this?

SecretCheck is a wrapper script that orchestrates several heavy-hitters in the secret-detection world (`gitleaks`, `trufflehog`) along with some custom "bonus" checks. The latter are optional (via --bonus) and will easily show false positives, but might still catch something the former tools did not find.
It's designed to be interactive, helpful, and easily specialized via an allowlist.

## Quick Start

Just drop `secretcheck.sh` into your PATH and run it from your repo's root folder:

```bash
secretcheck.sh
```

### Options

* `--bonus`: Opt-in to the "Bonus checks". These are templates for your own custom rules. We even added `your_own_secret` to the default search patterns to show you where to edit. By default, they search for generic keywords ("password") and risky filetypes (`.env`), but you are encouraged to edit the script and add specific patterns for your project (e.g., `GOOGLE_TK`, `INTERNAL_API_TOKEN`, `MY_HIDDEN_GEM` etc.).
* `--fail-all`: Perfect for CI/CD. The script will non-interactively fail and exit at the first sign of trouble.
* `--init-allowlist`: Creates a template `.secretcheck_allowed` file for you to start ignoring those annoying false positives.
* `--help`: Shows the help message.

### Environment Variables

* `RUN_BONUS=1`: Same as the `--bonus` flag.
* `FAIL_ALL=1`: Same as the `--fail-all` flag.
* `REPORT_DIR`: Where to store the raw logs (defaults to `.secretcheck`).
* `PRINT_ALLOWLISTED=1`: Show findings even if they are already on your allowlist.

## The Allowlist (.secretcheck_allowed)

Create a file named `.secretcheck_allowed` in your repo root. You can use glob patterns (fnmatch, like `tests/data/**` or `config/dummy_keys.json`) to tell SecretCheck: "I know about this file(s), I know for sure it's not a real danger, stop yelling at me."

## Support & Feedback ☕

If SecretCheck just saved you from a frantic API key rotation at 3 AM, maybe it's worth a small karma bonus? I'd be happy about a [digital coffee](https://buymeacoffee.com/arnwas) to help keep the paranoia high and the bugs low.

But honestly? Just **saying hello** or giving some feedback is even better! It's always nice to know that this slightly paranoid tool is actually out there helping someone.

Or found a bug, or have an idea? Open an issue or a PR!
