# Development and public-repository review

Target: https://github.com/aryanrawat00/Fraud-Sentinel-Agent-Firewall

Inspect current branch, status and remotes; do not assume an upstream exists.
Never reinitialize an existing repository, force-push, delete branches or replace
published history.

## Changes and verification

Keep changes small and necessary. Preserve unrelated work, credentials, databases
and backups. Follow the [offline runbook](docs/demo-runbook.md). Run checks relevant
to the change and record actual results, including failed or interrupted runs.
Do not install dependencies, enable live providers or migrate/reset databases
without explicit approval. Historical receipts are not fresh verification.

## Publication gates

1. Confirm the intended public repository and whether it contains history.
2. Review candidate source, templates, fixtures and documentation. Show the exact
   file list and obtain approval before staging.
3. Stage approved paths only; never git add . or git add -f.
4. Inspect git diff --cached --name-status, --stat, --check and the complete staged
   diff locally. Never paste a discovered secret into chat.
5. Obtain approval before committing; show the resulting summary and obtain
   separate approval before remote changes or pushing.
6. Recheck the remote before pushing. New/unrelated history requires review.
   Never bypass a non-fast-forward rejection.

Use OS/Git authentication; never embed tokens in commands or remote URLs.

## Public data boundary

Include source, migrations, manifests/lockfiles and reviewed synthetic fixtures.
Only non-secret defaults/placeholders belong in .env.example.
Exclude actual credentials, provider/audit keys, bearer tokens, real personal or
financial data, runtime SQLite files, journals/locks, backups, generated reports,
logs, build artifacts, tmp/ and root *-baseline.json / *-results.json receipts.

.gitignore cannot protect tracked files or secrets embedded in source. Review
content and paths. If a real credential is found, stop publication and arrange
revocation; do not silently rewrite history.

Historical browser configurations currently resolve a sibling Python environment.
Inspect them before use on a fresh clone; do not copy or publish that environment.
