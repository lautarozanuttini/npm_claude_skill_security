---
name: npm-security
description: >
  Security advisor for npm operations. Automatically activates whenever the user asks
  to install, update, add, or remove npm packages, run npm commands, manage dependencies,
  or discusses node_modules, package.json, or supply chain security. Also activates
  when the user asks about package vulnerabilities, CVEs, OWASP, or npm audit results.
  Use this skill to guide safe npm practices and reference the local vulnerability database.
---

# NPM Security Skill

This skill provides security guidance for all npm-related operations, backed by a local
vulnerability database aligned with OWASP Top 10 2021 and the NVD.

## Security Protocol for npm Operations

### Before Installing or Updating Packages

1. **Check the vulnerability database first** — scan `data/vulnerabilities.json` for the
   packages being installed. Alert the user if any match.

2. **Evaluate package health indicators:**
   - Weekly downloads (prefer > 100k for non-niche packages)
   - Last publish date (stale > 2 years is a risk signal)
   - Number of maintainers (single maintainer = higher takeover risk)
   - Repository activity (open issues, recent commits)

3. **Check for typosquatting** — alert if the package name is suspiciously similar to a
   popular package (e.g. `expres`, `lodahs`, `reakt`).

4. **Verify install source** — always use the official npm registry unless the project
   explicitly configures a private registry in `.npmrc`.

### Safe npm Commands Reference

| Intent | Safe Command | Notes |
|---|---|---|
| Install all deps | `npm ci` | Respects lock file exactly — use in CI |
| Add a package | `npm install <pkg> --save-exact` | Pins exact version |
| Update one package | `npm update <pkg>` | Stays within semver range |
| Check vulnerabilities | `npm audit` | Run after every install |
| Fix low-risk vulns | `npm audit fix` | Only semver-compatible fixes |
| Inspect a package | `npm pack <pkg>` | See what actually ships |
| Check package info | `npm view <pkg>` | Check publish date, maintainers |

### Hardening Recommendations — Suggest Proactively

When reviewing or setting up a project, recommend these mitigations:

1. **`ignore-scripts=true` in `.npmrc`** — blocks the primary supply chain vector.
   Malicious `postinstall`/`preinstall` hooks can't execute if scripts are disabled globally.
   ```
   # .npmrc
   ignore-scripts=true
   ```
   Tradeoff: packages that compile native binaries (esbuild, sharp, node-gyp) need
   their scripts re-enabled explicitly. Inform the user before recommending this.

2. **Pin exact versions in production `dependencies`** — avoid `^` and `~` ranges.
   A compromised minor/patch release installs automatically if the range allows it.
   Use `npm install <pkg> --save-exact` to pin on install.

3. **Use `overrides` to lock vulnerable transitive deps** — if a transitive dependency
   has a known vulnerability, pin it regardless of what the parent package requests:
   ```json
   "overrides": { "axios": "1.14.0" }
   ```
   This prevents a compromised version from entering the tree even transitively.

### Red Flags — Always Warn the User

- Installing with `--ignore-scripts=false` explicitly (scripts run during install)
- Adding `preinstall`/`postinstall` scripts from an unfamiliar package
- Version ranges like `^`, `~`, `*`, or `>=0.0.0` in production `dependencies`
- Packages requesting env vars, filesystem root access, or network in their install scripts
- Any package name not found on npmjs.com (may be private/internal — confirm with user)
- Using `npm install` in CI instead of `npm ci`

### OWASP Top 10 Quick Reference for npm

| OWASP Category | npm Relevance |
|---|---|
| A06:2021 Vulnerable and Outdated Components | Run `npm audit` before every deploy |
| A08:2021 Software and Data Integrity | Use `npm ci`, verify integrity hashes |
| A03:2021 Injection | Avoid packages using `eval()` or `child_process.exec()` |
| A01:2021 Broken Access Control | Check package filesystem/network permissions |
| A10:2021 SSRF | Validate URL-fetching packages |

Full OWASP Top 10 2021: https://owasp.org/www-project-top-ten/

## Behavior When Helping With npm Tasks

1. If the user asks to install a specific package, check `data/vulnerabilities.json` first.
2. If a match is found with HIGH or CRITICAL priority, **block the recommendation** and
   show the vulnerability details with CVE and OWASP category.
3. For MEDIUM/LOW, warn and let the user decide.
4. Always remind the user to run `npm audit` after any install.
5. If the vulnerability database is older than 30 days, suggest running `/update-security`.

## Incident Response — Suspected Compromise

If the user suspects a malicious package was installed, guide them through this protocol:

1. **Isolate** — disconnect the machine from the network if the install ran recently
   and the package had a suspicious `postinstall` script.

2. **Clean the environment:**
   ```bash
   npm cache clean --force
   rm -rf node_modules
   npm ci                  # reinstall from lockfile with verified integrity
   ```

3. **Rotate all credentials** that were present as environment variables or files
   during the install session (`process.env.*`, `.env`, AWS keys, tokens, SSH keys).

4. **Check for persistence** — known RAT indicators planted by supply chain attacks:
   - **macOS**: `launchctl list | grep -v apple`, look for unknown agents in `~/Library/LaunchAgents`
   - **Windows**: `Get-ScheduledTask` in PowerShell, check `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
   - **Linux**: `crontab -l`, `systemctl list-units --type=service --state=running`

5. **Audit what ran** — check npm debug logs at `~/.npm/_logs/` for the install session.
   Look for outbound HTTP calls in network logs during the install window.

6. **Report** — if confirmed malicious, report to npm security: security@npmjs.com
   and open a GitHub Advisory on the affected package's repository.

## Vulnerability Database Location

- Project DB: `data/vulnerabilities.json` (relative to plugin root)
- Global DB: `~/.claude/npm-security/vulnerabilities.json`

The hook script checks both paths in order.
