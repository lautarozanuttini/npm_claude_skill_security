# NPM Security Skill

## Prerequisite

**Python 3 is required** for the pre-execution hook. Install from https://python.org/downloads/
and ensure `py` (Windows launcher) or `python3` is in PATH.

To verify: `py --version`

## Structure

```
.claude-plugin/plugin.json     Plugin metadata
hooks/
  hooks.json                   PreToolUse hook config (fires on every Bash call)
  npm_security_hook.py         Intercepts npm install/update/add/ci commands
data/
  vulnerabilities.json         Local vulnerability DB (OWASP Top 10 2021 + CVEs)
skills/
  npm-security/SKILL.md        Auto-activated skill for npm security guidance
  update-security/SKILL.md     /update-security command
  security-list/SKILL.md       /security-list command
.claude/settings.json          Local hook activation for this project
```

## How it works

1. The **hook** (`npm_security_hook.py`) fires before every `Bash` tool call.
   - If the command is `npm install/update/add/ci`, it checks `data/vulnerabilities.json`
   - Shows a warning with matching vulnerabilities, OWASP categories, and CVEs
   - Exits 2 (blocks the command) — user must re-run to confirm
   - Only blocks once per unique command per session (no repeated interruptions)

2. The **skill** (`npm-security/SKILL.md`) activates automatically when discussing npm packages.
   - Claude reads the vulnerability DB before suggesting any install
   - Applies OWASP best practices to recommendations

3. **`/update-security`** — fetches fresh data from OWASP + GitHub Advisories + `npm audit`
   and updates `data/vulnerabilities.json`.

4. **`/security-list`** — prints all tracked vulnerabilities as:
   `YYYY-MM-DD - vulnerability description - PRIORITY`

## Disable hook temporarily

```bash
export NPM_SECURITY_DISABLED=1
npm install ...
```

## Vulnerability list format

```
2025-01-15 - Path traversal in express static middleware - HIGH
2024-06-12 - Malware in polyfill.io supply chain attack - CRITICAL
```
