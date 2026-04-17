#!/usr/bin/env python3
"""
NPM Security Hook for Claude Code
Intercepts npm install/update/add/ci commands and warns about known vulnerabilities
before execution. References OWASP Top 10 and the local vulnerability database.
"""

import json
import os
import re
import sys
from datetime import datetime

VULNERABILITY_PATHS = [
    os.path.join(os.path.dirname(__file__), "..", "data", "vulnerabilities.json"),
    os.path.expanduser("~/.claude/npm-security/vulnerabilities.json"),
]

STATE_FILE_TEMPLATE = os.path.expanduser("~/.claude/npm_security_state_{}.json")

NPM_MUTATING_COMMANDS = re.compile(
    r"\bnpm\s+(?:install|i|add|update|up|upgrade|ci|install-test|it)\b",
    re.IGNORECASE,
)

NPM_AUDIT_COMMANDS = re.compile(
    r"\bnpm\s+(?:audit)\b",
    re.IGNORECASE,
)

PRIORITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def load_vulnerabilities():
    for path in VULNERABILITY_PATHS:
        resolved = os.path.normpath(path)
        if os.path.exists(resolved):
            try:
                with open(resolved, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
    return None


def get_state_file(session_id):
    return STATE_FILE_TEMPLATE.format(session_id)


def load_state(session_id):
    path = get_state_file(session_id)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except (json.JSONDecodeError, IOError):
            pass
    return set()


def save_state(session_id, shown):
    path = get_state_file(session_id)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(list(shown), f)
    except IOError:
        pass


def extract_packages_from_command(command):
    """Extract package names being installed from npm install command."""
    match = re.search(
        r"\bnpm\s+(?:install|i|add)\s+(.*?)(?:\s*&&|\s*;|\s*\||$)",
        command,
        re.IGNORECASE,
    )
    if not match:
        return []

    args = match.group(1).strip()
    packages = []
    for token in args.split():
        if token.startswith("-"):
            continue
        # Remove version specifiers (@1.2.3 or @^1.2.3 etc.)
        pkg = re.split(r"@(?!.*\/)", token, maxsplit=1)[0] if "@" in token[1:] else token
        if pkg:
            packages.append(pkg.lower())
    return packages


def find_matching_vulnerabilities(db, packages):
    """Find vulnerabilities affecting any of the given packages."""
    vulns = db.get("vulnerabilities", [])
    if not packages:
        return vulns  # Return all if no specific packages (e.g. bare npm install)

    matched = []
    for v in vulns:
        pkg = v.get("package", "").lower()
        if any(p == pkg or p in pkg or pkg in p for p in packages):
            matched.append(v)
    return matched


def format_vulnerability_line(v):
    date = v.get("date", "????-??-??")
    name = v.get("vulnerability", "Unknown vulnerability")
    priority = v.get("priority", "UNKNOWN")
    return f"  {date} - {name} - {priority}"


def build_warning_message(command, db, matched_vulns):
    owasp_url = db.get("metadata", {}).get("owasp_source", "https://owasp.org/www-project-top-ten/")
    last_updated = db.get("metadata", {}).get("last_updated", "unknown")
    total_vulns = len(db.get("vulnerabilities", []))

    lines = [
        "╔══════════════════════════════════════════════════════════════╗",
        "║           NPM SECURITY GUARD — PRE-EXECUTION CHECK          ║",
        "╚══════════════════════════════════════════════════════════════╝",
        "",
        f"Command intercepted: {command.strip()[:80]}",
        "",
    ]

    if matched_vulns:
        sorted_vulns = sorted(matched_vulns, key=lambda v: PRIORITY_ORDER.get(v.get("priority", "INFO"), 99))
        critical_high = [v for v in sorted_vulns if v.get("priority") in ("CRITICAL", "HIGH")]

        if critical_high:
            lines.append("⚠️  KNOWN VULNERABILITIES DETECTED in packages being installed:")
        else:
            lines.append("ℹ️  Vulnerabilities found (low/medium severity):")

        for v in sorted_vulns[:10]:
            lines.append(format_vulnerability_line(v))
            cve = v.get("cve")
            ref = v.get("reference")
            owasp_cat = v.get("owasp_category")
            details = []
            if cve:
                details.append(f"CVE: {cve}")
            if owasp_cat:
                details.append(f"OWASP: {owasp_cat}")
            if ref:
                details.append(f"Ref: {ref}")
            if details:
                lines.append(f"     └─ {' | '.join(details)}")

        if len(sorted_vulns) > 10:
            lines.append(f"  ... and {len(sorted_vulns) - 10} more. Run /security-list to see all.")
    else:
        lines.append("✅ No specific vulnerabilities found for these packages in local DB.")
        lines.append("   (DB may be outdated — run /update-security to refresh)")

    lines += [
        "",
        "── Security Recommendations ──────────────────────────────────",
        "  • Run `npm audit` after install to check for new issues",
        "  • Pin exact versions in package.json to avoid supply-chain drift",
        "  • Review package permissions before adding new dependencies",
        f"  • OWASP Reference: {owasp_url}",
        f"  • Local DB: {total_vulns} entries, last updated {last_updated}",
        "",
        "  To proceed, re-run the same npm command.",
        "  To refresh vulnerability data, use: /update-security",
        "──────────────────────────────────────────────────────────────",
    ]

    return "\n".join(lines)


def main():
    if os.environ.get("NPM_SECURITY_DISABLED", "0") == "1":
        sys.exit(0)

    try:
        raw = sys.stdin.read()
        data = json.loads(raw)
    except (json.JSONDecodeError, Exception):
        sys.exit(0)

    tool_name = data.get("tool_name", "")
    if tool_name != "Bash":
        sys.exit(0)

    command = data.get("tool_input", {}).get("command", "")
    if not command:
        sys.exit(0)

    if not NPM_MUTATING_COMMANDS.search(command):
        sys.exit(0)

    session_id = data.get("session_id", "default")
    # Normalize command for dedup key
    dedup_key = re.sub(r"\s+", " ", command.strip())[:120]

    shown = load_state(session_id)
    if dedup_key in shown:
        # Already warned about this exact command in this session — allow it
        sys.exit(0)

    db = load_vulnerabilities()
    if db is None:
        print(
            "⚠️  NPM Security: vulnerability database not found. "
            "Run /update-security to initialize it.",
            file=sys.stderr,
        )
        shown.add(dedup_key)
        save_state(session_id, shown)
        sys.exit(2)

    packages = extract_packages_from_command(command)
    matched = find_matching_vulnerabilities(db, packages)

    warning = build_warning_message(command, db, matched)
    print(warning, file=sys.stderr)

    shown.add(dedup_key)
    save_state(session_id, shown)

    # Exit 2 = block execution and show message
    # User must re-run the command to proceed (second attempt is allowed)
    sys.exit(2)


if __name__ == "__main__":
    main()
