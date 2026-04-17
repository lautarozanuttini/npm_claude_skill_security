---
name: security-list
description: >
  Shows the full list of tracked npm vulnerabilities from the local database.
  Use when the user types /security-list or asks to "show vulnerabilities",
  "list security issues", "show npm CVEs", "what vulnerabilities do we track",
  or "show security database".
argument-hint: [--priority=CRITICAL|HIGH|MEDIUM|LOW] [--package=<name>] [--limit=<N>]
allowed-tools: [Read, Bash]
---

# /security-list

Displays the vulnerability database in the format: `${fecha} - ${vulnerabilidad} - ${prioridad}`

## Arguments

$ARGUMENTS

Supported filters (all optional):
- `--priority=HIGH` — filter by priority level (CRITICAL, HIGH, MEDIUM, LOW)
- `--package=lodash` — filter by package name (partial match)
- `--limit=20` — cap output at N entries (default: show all)

## Instructions

### Step 1 — Locate and read the database

Read `data/vulnerabilities.json` from the plugin/project root. If not found, try
`~/.claude/npm-security/vulnerabilities.json`. If neither exists, tell the user to
run `/update-security` first.

### Step 2 — Parse arguments

Parse `$ARGUMENTS` for filters:
- `--priority=X` → only show entries where `priority` matches X (case-insensitive)
- `--package=X` → only show entries where `package` contains X (case-insensitive)
- `--limit=N` → only show the first N entries after filtering

### Step 3 — Display the list

Print a header block:

```
╔══════════════════════════════════════════════════════════════╗
║              NPM SECURITY — VULNERABILITY LIST               ║
╚══════════════════════════════════════════════════════════════╝
  Database: data/vulnerabilities.json
  Entries:  {filtered} shown of {total} total
  Updated:  {last_updated}
  OWASP:    https://owasp.org/www-project-top-ten/
──────────────────────────────────────────────────────────────
```

Then for each vulnerability, sorted by date descending and then by priority
(CRITICAL → HIGH → MEDIUM → LOW), print exactly one line per entry:

```
{date} - {vulnerability} - {priority}
```

Example output:
```
2025-01-15 - Path traversal in express static middleware - HIGH
2024-09-01 - Prototype pollution in micromatch - HIGH
2024-06-12 - Malware in polyfill.io supply chain attack - CRITICAL
2024-03-29 - Backdoor in XZ Utils (liblzma) — supply chain attack - CRITICAL
2024-01-10 - SSRF in follow-redirects - MEDIUM
...
```

After the list, print a footer:

```
──────────────────────────────────────────────────────────────
  Legend: CRITICAL > HIGH > MEDIUM > LOW
  To refresh: /update-security
  To filter:  /security-list --priority=HIGH --package=axios
```

### Step 4 — OWASP Summary (when no filters are active)

If the user ran `/security-list` without filters, append a compact OWASP Top 10 breakdown:

```
── OWASP Top 10 2021 Coverage ────────────────────────────────
  A01 Broken Access Control        {N} entries
  A03 Injection                    {N} entries
  A06 Vulnerable Components        {N} entries  ← most common
  A08 Software/Data Integrity      {N} entries
  A10 SSRF                         {N} entries
  ... (only show categories with at least 1 entry)
──────────────────────────────────────────────────────────────
```

Count entries per `owasp_category` field from the database.
