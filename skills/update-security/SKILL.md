---
name: update-security
description: >
  Updates the npm security vulnerability database from OWASP and NVD sources.
  Use when the user types /update-security or asks to "refresh security data",
  "update vulnerabilities", "sync OWASP data", or "update npm security database".
argument-hint: [--project-only]
allowed-tools: [Bash, Read, Write, WebFetch, WebSearch]
---

# /update-security

Refreshes the local vulnerability database by fetching the latest data from OWASP
and running `npm audit` in the current project.

## Arguments

$ARGUMENTS

- `--project-only`: Only run `npm audit` for the current project; skip OWASP/NVD fetch.

## Instructions

### Step 1 — Locate the database file

Find the vulnerability database. Try these paths in order:
1. `data/vulnerabilities.json` relative to the plugin root (ask user to confirm the path
   if needed — it's typically next to this skill's parent directory)
2. `~/.claude/npm-security/vulnerabilities.json` as a global fallback

Read the current database to know what's already there.

### Step 2 — Fetch latest OWASP Top 10

Unless `--project-only` is passed:

1. Fetch the OWASP Top 10 page to check for updates:
   - https://owasp.org/www-project-top-ten/
2. Note if there is a newer version than 2021 (the current baseline).
3. If a new version exists, update the `owasp_top10_2021` entries and note the new version
   in `metadata.owasp_version`.

### Step 3 — Fetch recent npm advisories

Unless `--project-only` is passed:

Search for new high-priority npm advisories published since the database's `last_updated`:
- Use WebSearch to query: `site:github.com/advisories npm HIGH OR CRITICAL after:{last_updated}`
- Also check: https://github.com/advisories?query=type%3Areviewed+ecosystem%3Anpm
- Extract: package name, affected version range, CVE (if any), severity, OWASP category

For each new advisory found:
- Map severity to priority: `critical → CRITICAL`, `high → HIGH`, `moderate → MEDIUM`, `low → LOW`
- Map to closest OWASP Top 10 2021 category based on vulnerability type:
  - Injection/eval/prototype pollution → A03:2021
  - Outdated/abandoned packages → A06:2021
  - Supply chain/integrity → A08:2021
  - Path traversal/access → A01:2021
  - ReDoS/DoS → A06:2021
  - SSRF → A10:2021
  - Auth issues → A07:2021

### Step 4 — Run npm audit in current project

If a `package.json` exists in the current directory, run:

```bash
npm audit --json 2>/dev/null || npm audit 2>&1
```

Parse the output and add any new vulnerabilities that aren't already in the database.
For each finding from npm audit:
- Format: `${date} - ${vulnerability description} - ${priority}`
- Deduplicate against existing entries by matching package + CVE

### Step 5 — Write updated database

Update `data/vulnerabilities.json` with:
- `metadata.last_updated` set to today's date (YYYY-MM-DD format)
- New vulnerabilities appended to `vulnerabilities[]` array
- Keep existing entries (do not remove historical data)
- Sort vulnerabilities by date descending

### Step 6 — Report summary

Print a summary:

```
✅ Security database updated — {date}

  New vulnerabilities added: {N}
  Total entries in DB:       {total}
  OWASP version:             {version}
  Sources checked:
    • OWASP Top 10:         {owasp_url}
    • GitHub Advisories:    https://github.com/advisories
    • npm audit:            {project findings}

  Recent additions:
  {date} - {vulnerability} - {priority}
  ...

  Run /security-list to see the full list.
```

If no new vulnerabilities were found, say so explicitly — it's good news, not an error.
