import sys
import json
import re
import requests

import src.github_client as github_client

"""
CVE / OSV dependency vulnerability scanner.

Usage:

python -m src.checks.cve "https://github.com/OWNER/REPO/pull/NUMBER"
"""


# ================================================================
# SEVERITY
# ================================================================

SEVERITY_RANK = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MODERATE": 2,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}


def normalize_severity(severity):
    """Convert severity to one standard value."""

    if not severity:
        return "UNKNOWN"

    severity = str(severity).upper().strip()

    if severity == "MEDIUM":
        return "MODERATE"

    if severity in ("CRITICAL", "HIGH", "MODERATE", "LOW"):
        return severity

    return "UNKNOWN"


def highest_severity(current, new):
    """Return the highest severity between two values."""

    current = normalize_severity(current)
    new = normalize_severity(new)

    if SEVERITY_RANK[new] > SEVERITY_RANK[current]:
        return new

    return current


# ================================================================
# CVSS SEVERITY
# ================================================================


def cvss_to_severity(score):
    """Convert CVSS score into severity."""

    try:
        score = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"

    if score >= 9.0:
        return "CRITICAL"

    if score >= 7.0:
        return "HIGH"

    if score >= 4.0:
        return "MODERATE"

    if score > 0:
        return "LOW"

    return "UNKNOWN"


def get_osv_severity(vulnerability):
    """
    Get severity from OSV.

    Priority:
        1. database_specific.severity
        2. CVSS score
        3. UNKNOWN
    """

    database_specific = vulnerability.get(
        "database_specific",
        {},
    )

    severity = database_specific.get("severity")

    if severity:
        return normalize_severity(severity)

    severity_entries = vulnerability.get(
        "severity",
        [],
    )

    scores = []

    if isinstance(severity_entries, list):

        for entry in severity_entries:

            if not isinstance(entry, dict):
                continue

            score = entry.get("score")

            if not score:
                continue

            try:
                scores.append(float(score))
                continue

            except (TypeError, ValueError):
                pass

    if scores:

        highest_score = max(scores)

        return cvss_to_severity(highest_score)

    return "UNKNOWN"


# ================================================================
# SHORT REASON
# ================================================================


def clean_text(text):
    """Clean whitespace and Markdown from advisory text."""

    if not text:
        return ""

    text = re.sub(r"#+\s*", "", text)
    text = re.sub(r"\s+", " ", text)
    text = text.strip()

    return text


def make_short_reason(vulnerability):
    """Return a short human-readable explanation."""

    summary = vulnerability.get("summary")

    if summary:

        summary = clean_text(summary)

        if len(summary) > 300:
            summary = summary[:297] + "..."

        return summary

    details = clean_text(vulnerability.get("details"))

    if not details:
        return "A known security vulnerability affects this dependency."

    sentences = re.split(
        r"(?<=[.!?])\s+",
        details,
    )

    reason = sentences[0].strip()

    if len(reason) > 300:
        reason = reason[:297] + "..."

    return reason


# ================================================================
# FIXED VERSION
# ================================================================


def get_fixed_versions(vulnerability):
    """Extract patched versions reported by OSV."""

    fixed_versions = []

    for affected in vulnerability.get(
        "affected",
        [],
    ):

        for range_data in affected.get(
            "ranges",
            [],
        ):

            for event in range_data.get(
                "events",
                [],
            ):

                fixed = event.get("fixed")

                if fixed:
                    fixed_versions.append(str(fixed))

    return fixed_versions


def make_solution(package, vulnerability):
    """Create a concise remediation recommendation."""

    fixed_versions = get_fixed_versions(vulnerability)

    if fixed_versions:

        return f"Upgrade {package} to {fixed_versions[0]} or later."

    return (
        f"Upgrade {package} to a patched version "
        f"recommended by the security advisory."
    )


# ================================================================
# VULNERABILITY IDENTIFICATION
# ================================================================


def normalize_for_comparison(text):
    """Normalize text so similar advisory descriptions can be compared."""

    if not text:
        return ""

    text = text.lower()

    text = re.sub(r"[`*_#]", "", text)

    text = re.sub(
        r"^(django|flask|requests|urllib3|jinja2)\s*:\s*",
        "",
        text,
    )

    text = re.sub(r"\s+", " ", text)

    text = re.sub(r"[^\w\s]", " ", text)

    text = re.sub(r"\s+", " ", text)

    return text.strip()


def get_vulnerability_key(vulnerability):
    """Generate a key for duplicate detection."""

    aliases = vulnerability.get(
        "aliases",
        [],
    )

    if aliases:

        ghsa_aliases = [
            alias for alias in aliases if str(alias).upper().startswith("GHSA-")
        ]

        if ghsa_aliases:

            return (
                "ALIAS:",
                ghsa_aliases[0].upper(),
            )

        return (
            "ALIAS:",
            str(aliases[0]).upper(),
        )

    summary = normalize_for_comparison(vulnerability.get("summary"))

    if summary:

        return (
            "SUMMARY:",
            summary,
        )

    details = normalize_for_comparison(vulnerability.get("details"))

    if details:

        return (
            "DETAILS:",
            details[:500],
        )

    return (
        "ID:",
        vulnerability.get("id"),
    )


# ================================================================
# ADVISORY PREFERENCE
# ================================================================


def advisory_priority(vulnerability):
    """
    Prefer advisories in this order:

        GHSA
        CVE
        PYSEC
        other
    """

    vuln_id = str(vulnerability.get("id", "")).upper()

    if vuln_id.startswith("GHSA-"):
        return 4

    if vuln_id.startswith("CVE-"):
        return 3

    if vuln_id.startswith("PYSEC-"):
        return 2

    return 1


def merge_vulnerability(existing, new):
    """Merge two records representing the same vulnerability."""

    existing_severity = normalize_severity(existing.get("severity"))

    new_severity = normalize_severity(new.get("severity"))

    if advisory_priority(new) > advisory_priority(existing):

        existing["id"] = new.get("id")

        if new.get("summary"):
            existing["summary"] = new.get("summary")

    existing["severity"] = highest_severity(
        existing_severity,
        new_severity,
    )

    if not existing.get("summary") and new.get("summary"):

        existing["summary"] = new.get("summary")

    existing_solution = existing.get(
        "solution",
        "",
    )

    new_solution = new.get(
        "solution",
        "",
    )

    if (
        "patched version" in existing_solution.lower()
        and "upgrade" in new_solution.lower()
    ):

        existing["solution"] = new_solution

    return existing


def deduplicate_vulnerabilities(vulnerabilities):
    """Remove duplicate GHSA/PYSEC records."""

    grouped = {}

    for vulnerability in vulnerabilities:

        key = get_vulnerability_key(vulnerability)

        if key not in grouped:

            grouped[key] = vulnerability

        else:

            grouped[key] = merge_vulnerability(
                grouped[key],
                vulnerability,
            )

    return list(grouped.values())


# ================================================================
# DEPENDENCY EXTRACTION
# ================================================================

DEPENDENCY_ECOSYSTEMS = {
    "package.json": "npm",
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "requirements.txt": "PyPI",
    "pyproject.toml": "PyPI",
    "pipfile": "PyPI",
    "pipfile.lock": "PyPI",
    "go.mod": "Go",
    "go.sum": "Go",
    "pom.xml": "Maven",
    "build.gradle": "Maven",
    "build.gradle.kts": "Maven",
    "cargo.toml": "crates.io",
    "cargo.lock": "crates.io",
    "gemfile": "RubyGems",
    "gemfile.lock": "RubyGems",
    "composer.json": "Packagist",
    # Current project's test dependency files.
    "dependencies-nested.json": "PyPI",
    "dependencies-simple.json": "PyPI",
}


def extract_dependencies(details):
    """Extract dependencies from added/changed PR lines."""

    result = []

    for filename, patch in details["changed_files"]:

        filename_lower = filename.lower()

        if filename_lower not in DEPENDENCY_ECOSYSTEMS:
            continue

        # ========================================================
        # requirements.txt
        # ========================================================

        if filename_lower.endswith(".txt"):

            lines = patch.splitlines()

            lineno = None

            for line in lines:

                if line.startswith("@@"):

                    parts = line.split()

                    for part in parts:

                        if part.startswith("+"):

                            start = part.split(",")[0]

                            lineno = int(start[1:])

                            break

                    continue

                if line.startswith(("---", "+++")):
                    continue

                if line.startswith("-"):
                    continue

                if line.startswith("+"):

                    content = line[1:].strip()

                    if content and not content.startswith("#"):

                        for operator in (
                            "==",
                            ">=",
                            "<=",
                            "~=",
                            ">",
                            "<",
                        ):

                            if operator in content:

                                package, version = content.split(
                                    operator,
                                    1,
                                )

                                package = package.strip()
                                version = version.strip()

                                if package and version:

                                    result.append(
                                        (
                                            filename,
                                            package,
                                            version,
                                            lineno,
                                        )
                                    )

                                break

                    if lineno is not None:
                        lineno += 1

                elif line.startswith(" "):

                    if lineno is not None:
                        lineno += 1

            continue

        # ========================================================
        # JSON dependency files
        # ========================================================

        lines = patch.splitlines()

        lineno = None
        added_lines = []
        dependency_lines = {}

        for line in lines:

            if line.startswith("@@"):

                parts = line.split()

                for part in parts:

                    if part.startswith("+"):

                        start = part.split(",")[0]

                        lineno = int(start[1:])

                        break

                continue

            if line.startswith(("---", "+++")):
                continue

            if line.startswith("-"):
                continue

            if line.startswith("+"):

                content = line[1:].strip()

                if lineno is not None:
                    lineno += 1

                added_lines.append(content)

                match = re.match(
                    r'^"([^"]+)"\s*:\s*(?:"([^"]+)"|\{)',
                    content,
                )

                if match:

                    package_name = match.group(1)

                    dependency_lines[package_name] = lineno

        json_text = "\n".join(added_lines)

        try:

            data = json.loads(json_text)

        except json.JSONDecodeError:

            continue

        # ========================================================
        # Nested JSON
        # ========================================================

        if isinstance(data, dict) and "dependencies" in data:

            dependencies = data["dependencies"]

            if isinstance(dependencies, dict):

                for package_name, package_details in dependencies.items():

                    dependency_line = dependency_lines.get(package_name)

                    if isinstance(package_details, dict):

                        version = package_details.get("version")

                    else:

                        version = package_details

                    if package_name and version:

                        result.append(
                            (
                                filename,
                                package_name,
                                str(version),
                                dependency_line,
                            )
                        )

        # ========================================================
        # Simple JSON
        # ========================================================

        elif isinstance(data, dict):

            for package_name, version in data.items():

                if package_name in dependency_lines:

                    result.append(
                        (
                            filename,
                            package_name,
                            str(version),
                            dependency_lines[package_name],
                        )
                    )

    return result


# ================================================================
# OSV API
# ================================================================


def query_osv(
    package,
    ecosystem,
    version,
):
    """Query OSV for a package/version."""

    payload = {
        "package": {
            "name": package,
            "ecosystem": ecosystem,
        },
        "version": version,
    }

    try:

        response = requests.post(
            "https://api.osv.dev/v1/query",
            json=payload,
            timeout=20,
        )

        response.raise_for_status()

        return response.json()

    except requests.RequestException as error:

        print(
            f"Warning: OSV query failed for " f"{package} {version}: {error}",
            file=sys.stderr,
        )

        return {}


# ================================================================
# MAIN CVE CHECK
# ================================================================


def check_vulnerabilities(
    pr_url,
    include_details=False,
):
    """
    Scan PR dependency changes against OSV.

    include_details:
        True  -> include reasons and recommendations.
        False -> return only core vulnerability information.
    """

    details = github_client.fetch_pr_details(pr_url)

    if not details:
        return []

    dependencies = extract_dependencies(details)

    print("\n===== CVE / OSV SCAN =====")

    print(f"Dependencies detected: " f"{len(dependencies)}")

    if not dependencies:

        print("No dependency changes found.")

        print("Result: ALLOW")

        return []

    # ------------------------------------------------------------
    # Query each dependency.
    # ------------------------------------------------------------

    raw_vulnerabilities = []

    for (
        filename,
        package,
        version,
        lineno,
    ) in dependencies:

        ecosystem = DEPENDENCY_ECOSYSTEMS.get(filename.lower())

        if not ecosystem:
            continue

        response_data = query_osv(
            package,
            ecosystem,
            version,
        )

        for vulnerability in response_data.get(
            "vulns",
            [],
        ):

            vulnerability_record = {
                "filename": filename,
                "package": package,
                "version": version,
                "line": lineno,
                "id": vulnerability.get("id"),
                "aliases": vulnerability.get(
                    "aliases",
                    [],
                ),
                "summary": vulnerability.get("summary"),
                "severity": get_osv_severity(vulnerability),
                "reason": make_short_reason(vulnerability),
                "solution": make_solution(
                    package,
                    vulnerability,
                ),
            }

            if vulnerability_record["id"]:

                raw_vulnerabilities.append(vulnerability_record)

    # ------------------------------------------------------------
    # Deduplicate by package + vulnerability.
    # ------------------------------------------------------------

    package_groups = {}

    for finding in raw_vulnerabilities:

        aliases = finding.get(
            "aliases",
            [],
        )

        ghsa_aliases = [
            alias for alias in aliases if str(alias).upper().startswith("GHSA-")
        ]

        if ghsa_aliases:

            vulnerability_identity = ghsa_aliases[0].upper()

        else:

            vulnerability_identity = finding["id"].upper()

        key = (
            finding["package"].lower(),
            vulnerability_identity,
        )

        if key not in package_groups:

            package_groups[key] = finding

        else:

            existing = package_groups[key]

            if advisory_priority(finding) > advisory_priority(existing):

                existing["id"] = finding["id"]

            existing["severity"] = highest_severity(
                existing["severity"],
                finding["severity"],
            )

            if not existing.get("summary") and finding.get("summary"):

                existing["summary"] = finding["summary"]

    vulnerabilities = list(package_groups.values())

    # ============================================================
    # FINAL RESULT
    # ============================================================

    highest = "UNKNOWN"

    for finding in vulnerabilities:

        highest = highest_severity(
            highest,
            finding["severity"],
        )

    if vulnerabilities:
        verdict = "BLOCK"
    else:
        verdict = "ALLOW"

    print("\n===== CVE / OSV SCAN SUMMARY =====")

    print(f"Dependencies checked: " f"{len(dependencies)}")

    print(f"Unique vulnerabilities found: " f"{len(vulnerabilities)}")

    print(f"Highest severity: " f"{highest}")

    print(f"Result: " f"{verdict}")

    # ============================================================
    # DETAIL OUTPUT
    # ============================================================

    if include_details:

        print("\n===== VULNERABILITY DETAILS =====")

        if not vulnerabilities:

            print("No vulnerabilities found.")

        else:

            for index, finding in enumerate(
                vulnerabilities,
                start=1,
            ):

                print(f"\n[{index}] " f"{finding['package']} " f"{finding['version']}")

                print(f"File: " f"{finding['filename']}")

                if finding["line"] is not None:

                    print(f"Line: " f"{finding['line']}")

                print(f"Severity: " f"{finding['severity']}")

                print(f"ID: " f"{finding['id']}")

                if finding.get("summary"):

                    print(f"Vulnerability: " f"{finding['summary']}")

                print(f"Reason: " f"{finding['reason']}")

                print(f"Recommendation: " f"{finding['solution']}")

    # ============================================================
    # SHORT OUTPUT
    # ============================================================

    else:

        print("\n===== VULNERABILITY SUMMARY =====")

        if not vulnerabilities:

            print("No vulnerabilities found.")

        else:

            for index, finding in enumerate(
                vulnerabilities,
                start=1,
            ):

                print(
                    f"{index}. "
                    f"{finding['package']} "
                    f"{finding['version']} - "
                    f"{finding['severity']} - "
                    f"{finding['id']}"
                )

                if finding.get("summary"):

                    print(f"   {finding['summary']}")

    # ============================================================
    # RETURN TO main.py
    # ============================================================

    return vulnerabilities


# ================================================================
# DIRECT EXECUTION
# ================================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print("Usage: " "python -m src.checks.cve " "<GitHub Pull Request URL>")

        sys.exit(1)

    pr_url = sys.argv[1]

    # Direct execution still works.
    # Details are disabled by default because main.py
    # is now responsible for the single user choice.
    check_vulnerabilities(
        pr_url,
        include_details=False,
    )
