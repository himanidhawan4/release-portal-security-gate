import json
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

import requests

from src import github_client

# ============================================================
# CONFIGURATION
# ============================================================

OSV_API_URL = "https://api.osv.dev/v1/query"

DEPENDENCY_ECOSYSTEMS = {
    "requirements.txt": "PyPI",
    "package.json": "npm",
    "package-lock.json": "npm",
}

REQUEST_TIMEOUT = 15


# ============================================================
# SEVERITY
# ============================================================

SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "MODERATE": 3,
    "LOW": 2,
    "UNKNOWN": 1,
}


def normalize_severity(
    severity: Optional[str],
) -> str:
    """
    Convert severity into a common format.
    """

    if not severity:
        return "UNKNOWN"

    value = str(severity).upper().strip()

    if value in {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "MODERATE",
        "LOW",
    }:
        return value

    return "UNKNOWN"


# ============================================================
# CVSS HELPERS
# ============================================================


def cvss_v3_score_to_severity(
    score: float,
) -> str:
    """
    Convert a CVSS v3 score to severity.
    """

    if score >= 9.0:
        return "CRITICAL"

    if score >= 7.0:
        return "HIGH"

    if score >= 4.0:
        return "MEDIUM"

    if score > 0.0:
        return "LOW"

    return "UNKNOWN"


def cvss_v4_score_to_severity(
    score: float,
) -> str:
    """
    Convert a CVSS v4 score to severity.
    """

    if score >= 9.0:
        return "CRITICAL"

    if score >= 7.0:
        return "HIGH"

    if score >= 4.0:
        return "MEDIUM"

    if score > 0.0:
        return "LOW"

    return "UNKNOWN"


def get_cvss_score(
    vulnerability: Dict[str, Any],
) -> Optional[float]:
    """
    Extract the highest available CVSS score.
    """

    scores: List[float] = []

    database_specific = vulnerability.get("database_specific")

    if isinstance(database_specific, dict):

        score = database_specific.get("cvss_score")

        if isinstance(
            score,
            (int, float),
        ):
            scores.append(float(score))

    severity_entries = vulnerability.get("severity")

    if isinstance(
        severity_entries,
        list,
    ):

        for entry in severity_entries:

            if not isinstance(
                entry,
                dict,
            ):
                continue

            score = entry.get("score")

            if isinstance(
                score,
                (int, float),
            ):
                scores.append(float(score))

    if not scores:
        return None

    return max(scores)


def get_severity(
    vulnerability: Dict[str, Any],
) -> str:
    """
    Determine vulnerability severity.

    Priority:
    1. database_specific severity
    2. CVSS score
    3. severity entries
    4. UNKNOWN
    """

    database_specific = vulnerability.get("database_specific")

    if isinstance(
        database_specific,
        dict,
    ):

        database_severity = database_specific.get("severity")

        if database_severity:
            normalized = normalize_severity(str(database_severity))

            if normalized != "UNKNOWN":
                return normalized

    score = get_cvss_score(vulnerability)

    if score is not None:
        return cvss_v3_score_to_severity(score)

    severity_entries = vulnerability.get("severity")

    if isinstance(
        severity_entries,
        list,
    ):

        for entry in severity_entries:

            if not isinstance(
                entry,
                dict,
            ):
                continue

            severity_value = entry.get("type")

            if severity_value:

                normalized = normalize_severity(str(severity_value))

                if normalized != "UNKNOWN":
                    return normalized

    return "UNKNOWN"


# ============================================================
# PATCH PARSING
# ============================================================


def get_added_lines(
    patch: str,
) -> List[Tuple[int, str]]:
    """
    Return only added lines from a GitHub patch.

    Returns:
        [(line_number, line_content), ...]
    """

    if not patch:
        return []

    results: List[Tuple[int, str]] = []

    current_line = 0

    hunk_pattern = re.compile(r"@@ -\d+(?:,\d+)? " r"\+(\d+)(?:,\d+)? @@")

    for raw_line in patch.splitlines():

        hunk_match = hunk_pattern.match(raw_line)

        if hunk_match:
            current_line = int(hunk_match.group(1))
            continue

        if raw_line.startswith("\\"):
            continue

        if raw_line.startswith("+"):

            if raw_line.startswith("+++"):
                continue

            results.append(
                (
                    current_line,
                    raw_line[1:],
                )
            )

            current_line += 1
            continue

        if raw_line.startswith("-"):

            if raw_line.startswith("---"):
                continue

            continue

        if current_line:
            current_line += 1

    return results


# ============================================================
# REQUIREMENTS.TXT
# ============================================================


def parse_requirements_line(
    line: str,
) -> Optional[Tuple[str, str]]:
    """
    Parse an exact version dependency from requirements.txt.
    """

    line = line.strip()

    if not line:
        return None

    if line.startswith("#"):
        return None

    line = line.split(
        "#",
        1,
    )[0].strip()

    pattern = re.match(
        r"^([A-Za-z0-9_.-]+)\s*" r"(==|>=|<=|>|<|~=)\s*" r"([A-Za-z0-9!+_.-]+)",
        line,
    )

    if not pattern:
        return None

    package = pattern.group(1)
    operator = pattern.group(2)
    version = pattern.group(3)

    # Only exact versions are scanned.
    if operator != "==":
        return None

    return package, version


# ============================================================
# PACKAGE.JSON
# ============================================================


def parse_package_json(
    line: str,
) -> Optional[Tuple[str, str]]:
    """
    Parse an added dependency from package.json.
    """

    pattern = re.match(
        r'\s*"([^"]+)"\s*:\s*"([^"]+)"',
        line.strip().rstrip(","),
    )

    if not pattern:
        return None

    package = pattern.group(1)
    version_spec = pattern.group(2).strip()

    version_spec = re.sub(
        r"^[~^<>=\s]+",
        "",
        version_spec,
    )

    version_match = re.match(
        r"(\d+(?:\.\d+){0,2}" r"(?:[-+][A-Za-z0-9.-]+)?)",
        version_spec,
    )

    if not version_match:
        return None

    version = version_match.group(1)

    return package, version


# ============================================================
# PACKAGE-LOCK.JSON
# ============================================================


def clean_npm_version(
    version: str,
) -> Optional[str]:
    """
    Clean an npm version string.
    """

    if not version:
        return None

    version = version.strip()

    version = re.sub(
        r"^[~^<>=vV\s]+",
        "",
        version,
    )

    match = re.match(
        r"(\d+(?:\.\d+){0,2}" r"(?:[-+][A-Za-z0-9.-]+)?)",
        version,
    )

    if not match:
        return None

    return match.group(1)


def parse_package_lock_line(
    line: str,
) -> Optional[Tuple[str, str]]:
    """
    Parse a dependency from an added package-lock.json line.
    """

    pattern = re.match(
        r'\s*"([^"]+)"\s*:\s*"([^"]+)"',
        line.strip().rstrip(","),
    )

    if not pattern:
        return None

    package = pattern.group(1)

    version = clean_npm_version(pattern.group(2))

    if not version:
        return None

    return package, version


# ============================================================
# VERSION HELPERS
# ============================================================


def parse_version_tuple(
    version: Optional[str],
) -> Optional[Tuple[int, int, int]]:
    """
    Convert a basic semantic version into:
        (major, minor, patch)

    Pre-release/build metadata is ignored.
    """

    if not version:
        return None

    version = str(version).strip()

    version = re.sub(
        r"^[vV]",
        "",
        version,
    )

    match = re.match(
        r"^(\d+)" r"(?:\.(\d+))?" r"(?:\.(\d+))?",
        version,
    )

    if not match:
        return None

    major = int(match.group(1))

    minor = int(match.group(2) or 0)

    patch = int(match.group(3) or 0)

    return major, minor, patch


def clean_fixed_version(
    version: str,
) -> Optional[str]:
    """
    Clean an OSV fixed version.
    """

    if not version:
        return None

    version = str(version).strip()

    version = re.sub(
        r"^[vV]",
        "",
        version,
    )

    parsed = parse_version_tuple(version)

    if not parsed:
        return None

    return version


def choose_fixed_version(
    installed_version: str,
    fixed_versions: List[str],
) -> Optional[str]:
    """
    Choose the smallest fixed version that is newer
    than the installed version.
    """

    installed = parse_version_tuple(installed_version)

    if not installed:
        return None

    valid_versions = []

    for version in fixed_versions:

        cleaned = clean_fixed_version(str(version))

        if not cleaned:
            continue

        parsed = parse_version_tuple(cleaned)

        if not parsed:
            continue

        if parsed > installed:

            valid_versions.append(
                (
                    parsed,
                    cleaned,
                )
            )

    if not valid_versions:
        return None

    valid_versions.sort(key=lambda item: item[0])

    return valid_versions[0][1]


# ============================================================
# AFFECTED VERSION CHECK
# ============================================================


def version_is_affected(
    installed_version: str,
    events: List[Any],
) -> Tuple[bool, Optional[str]]:
    """
    Check whether the installed version falls inside
    an OSV introduced/fixed range.
    """

    installed = parse_version_tuple(installed_version)

    if not installed:
        return False, None

    introduced_version = None

    for event in events:

        if not isinstance(
            event,
            dict,
        ):
            continue

        introduced = event.get("introduced")

        if introduced is not None:

            introduced_text = str(introduced).strip()

            if introduced_text == "0":
                introduced_version = None
            else:
                introduced_version = parse_version_tuple(introduced_text)

        fixed = event.get("fixed")

        if fixed is not None:

            fixed_text = clean_fixed_version(str(fixed))

            fixed_version = parse_version_tuple(fixed_text)

            if fixed_version:

                lower_ok = introduced_version is None or installed >= introduced_version

                if lower_ok and installed < fixed_version:
                    return True, fixed_text

                introduced_version = None

        last_affected = event.get("last_affected")

        if last_affected is not None:

            last_text = clean_fixed_version(str(last_affected))

            last_version = parse_version_tuple(last_text)

            if last_version:

                lower_ok = introduced_version is None or installed >= introduced_version

                if lower_ok and installed <= last_version:
                    return True, None

                introduced_version = None

    return False, None


def get_affected_status(
    vulnerability: Dict[str, Any],
    installed_version: str,
) -> Tuple[bool, Optional[str]]:
    """
    Check whether the installed version is actually affected.

    If an OSV entry contains an explicit versions list and
    the installed version is not in that list, the entry is
    ignored.

    This prevents false positives from unrelated version
    branches.
    """

    affected = vulnerability.get("affected")

    if (
        not isinstance(
            affected,
            list,
        )
        or not affected
    ):
        return True, None

    has_version_information = False

    for entry in affected:

        if not isinstance(
            entry,
            dict,
        ):
            continue

        versions = entry.get("versions")

        # ----------------------------------------------------
        # Explicit affected versions
        # ----------------------------------------------------

        if (
            isinstance(
                versions,
                list,
            )
            and versions
        ):

            has_version_information = True

            version_set = {str(version).strip() for version in versions}

            # IMPORTANT:
            # If the installed version is not explicitly
            # listed, do not fall through to ranges.
            if installed_version not in version_set:
                continue

            ranges = entry.get("ranges")

            if isinstance(
                ranges,
                list,
            ):

                for range_entry in ranges:

                    if not isinstance(
                        range_entry,
                        dict,
                    ):
                        continue

                    events = range_entry.get("events")

                    if not isinstance(
                        events,
                        list,
                    ):
                        continue

                    affected_version, fixed_version = version_is_affected(
                        installed_version,
                        events,
                    )

                    if affected_version:
                        return (
                            True,
                            fixed_version,
                        )

            return True, None

        # ----------------------------------------------------
        # Range information
        # ----------------------------------------------------

        ranges = entry.get("ranges")

        if not isinstance(
            ranges,
            list,
        ):
            continue

        for range_entry in ranges:

            if not isinstance(
                range_entry,
                dict,
            ):
                continue

            events = range_entry.get("events")

            if not isinstance(
                events,
                list,
            ):
                continue

            if not events:
                continue

            has_version_information = True

            affected_version, fixed_version = version_is_affected(
                installed_version,
                events,
            )

            if affected_version:
                return (
                    True,
                    fixed_version,
                )

    if has_version_information:
        return False, None

    return True, None


# ============================================================
# OSV API
# ============================================================


def query_osv(
    package: str,
    version: str,
    ecosystem: str,
) -> List[Dict[str, Any]]:
    """
    Query OSV for a package/version.
    """

    payload = {
        "package": {
            "name": package,
            "ecosystem": ecosystem,
        },
        "version": version,
    }

    try:

        response = requests.post(
            OSV_API_URL,
            json=payload,
            timeout=REQUEST_TIMEOUT,
        )

        response.raise_for_status()

        data = response.json()

    except requests.RequestException as exc:

        print(
            f"OSV request failed for " f"{package} {version}: {exc}",
            file=sys.stderr,
        )

        raise

    except ValueError:

        print(
            "OSV returned invalid JSON.",
            file=sys.stderr,
        )

        raise

    vulnerabilities = data.get(
        "vulns",
        [],
    )

    if not isinstance(
        vulnerabilities,
        list,
    ):
        return []

    return vulnerabilities


# ============================================================
# OSV ADVISORY DEDUPLICATION
# ============================================================


def get_advisory_identifiers(
    vulnerability: Dict[str, Any],
) -> set:
    """
    Return the vulnerability ID and all aliases.

    Example:

        GHSA-xxxx
        PYSEC-xxxx

    may appear in the same OSV record's aliases.
    """

    identifiers = set()

    vulnerability_id = vulnerability.get("id")

    if vulnerability_id:
        identifiers.add(str(vulnerability_id).strip().upper())

    aliases = vulnerability.get("aliases")

    if isinstance(
        aliases,
        list,
    ):

        for alias in aliases:

            if alias:
                identifiers.add(str(alias).strip().upper())

    return identifiers


def advisory_priority(
    vulnerability: Dict[str, Any],
) -> Tuple[int, int]:
    """
    Decide which duplicate advisory should be kept.

    Preference:
    1. GHSA advisory
    2. Advisory with known severity
    """

    vulnerability_id = str(
        vulnerability.get(
            "id",
            "",
        )
    ).upper()

    severity = get_severity(vulnerability)

    ghsa_priority = 2 if vulnerability_id.startswith("GHSA-") else 1

    severity_priority = SEVERITY_ORDER.get(
        severity,
        0,
    )

    return (
        ghsa_priority,
        severity_priority,
    )


def deduplicate_osv_vulnerabilities(
    vulnerabilities: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Remove duplicate OSV advisories.

    GHSA and PYSEC records can describe the same underlying
    vulnerability.

    Example:

        GHSA-xxxx
        PYSEC-xxxx

    If their identifiers/aliases overlap, they are treated
    as the same vulnerability.

    The preferred record is kept, normally the GHSA record
    because it usually contains the useful severity data.
    """

    groups: List[
        Tuple[
            set,
            Dict[str, Any],
        ]
    ] = []

    for vulnerability in vulnerabilities:

        if not isinstance(
            vulnerability,
            dict,
        ):
            continue

        identifiers = get_advisory_identifiers(vulnerability)

        if not identifiers:
            groups.append(
                (
                    set(),
                    vulnerability,
                )
            )
            continue

        matched_group = None

        for index, (
            group_identifiers,
            existing_vulnerability,
        ) in enumerate(groups):

            if identifiers.intersection(group_identifiers):

                matched_group = index
                break

        if matched_group is None:

            groups.append(
                (
                    set(identifiers),
                    vulnerability,
                )
            )

            continue

        group_identifiers, existing_vulnerability = groups[matched_group]

        combined_identifiers = group_identifiers | identifiers

        current_priority = advisory_priority(vulnerability)

        existing_priority = advisory_priority(existing_vulnerability)

        if current_priority > existing_priority:

            groups[matched_group] = (
                combined_identifiers,
                vulnerability,
            )

        else:

            groups[matched_group] = (
                combined_identifiers,
                existing_vulnerability,
            )

    return [vulnerability for _, vulnerability in groups]


# ============================================================
# FIXED VERSION EXTRACTION
# ============================================================


def get_fixed_versions(
    vulnerability: Dict[str, Any],
) -> List[str]:
    """
    Extract fixed versions from an OSV vulnerability.
    """

    fixed_versions: List[str] = []

    affected = vulnerability.get("affected")

    if not isinstance(
        affected,
        list,
    ):
        return fixed_versions

    for entry in affected:

        if not isinstance(
            entry,
            dict,
        ):
            continue

        ranges = entry.get("ranges")

        if not isinstance(
            ranges,
            list,
        ):
            continue

        for range_entry in ranges:

            if not isinstance(
                range_entry,
                dict,
            ):
                continue

            events = range_entry.get("events")

            if not isinstance(
                events,
                list,
            ):
                continue

            for event in events:

                if not isinstance(
                    event,
                    dict,
                ):
                    continue

                fixed = event.get("fixed")

                if fixed is not None:

                    cleaned = clean_fixed_version(str(fixed))

                    if cleaned:
                        fixed_versions.append(cleaned)

    return list(dict.fromkeys(fixed_versions))


# ============================================================
# REASON
# ============================================================


def build_reason(
    package: str,
    version: str,
    vulnerability: Dict[str, Any],
) -> str:
    """
    Build a concise explanation.
    """

    summary = vulnerability.get("summary")

    if summary:
        return str(summary)

    details = vulnerability.get("details")

    if details:

        details = str(details)

        return details[:500]

    return f"{package} {version} is affected " "by a known vulnerability."


# ============================================================
# RECOMMENDATION
# ============================================================


def build_recommendation(
    package: str,
    version: str,
    vulnerability: Dict[str, Any],
) -> str:
    """
    Build an upgrade recommendation.
    """

    fixed_versions = get_fixed_versions(vulnerability)

    fixed_version = choose_fixed_version(
        version,
        fixed_versions,
    )

    if fixed_version:

        return (
            f"Upgrade {package} from "
            f"{version} to {fixed_version} "
            "or a newer secure release."
        )

    return f"Upgrade {package} from {version} " "to the latest secure release."


def build_branch_specific_recommendation(
    package: str,
    version: str,
    vulnerability: Dict[str, Any],
) -> str:
    """
    Build a branch-specific recommendation.
    """

    return build_recommendation(
        package,
        version,
        vulnerability,
    )


# ============================================================
# MAIN CVE CHECK
# ============================================================


def check_vulnerabilities(
    pr_url: str,
    include_details: bool = False,
) -> Dict[str, Any]:
    """
    Scan dependencies changed in a GitHub Pull Request.

    Only added dependency lines are scanned.

    Source-code contents are never stored in the result.
    """

    details = github_client.fetch_pr_details(pr_url)

    findings: List[Dict[str, Any]] = []

    # Unique dependency:
    # package + version + ecosystem
    scanned_dependencies = set()

    total_dependencies = 0

    changed_files = details.get(
        "changed_files",
        [],
    )

    for file_name, patch in changed_files:

        ecosystem = None

        if file_name.endswith("requirements.txt"):
            ecosystem = "PyPI"

        elif file_name.endswith("package.json"):
            ecosystem = "npm"

        elif file_name.endswith("package-lock.json"):
            ecosystem = "npm"

        else:
            continue

        added_lines = get_added_lines(patch)

        for line_number, line in added_lines:

            dependency = None

            # ------------------------------------------------
            # requirements.txt
            # ------------------------------------------------

            if file_name.endswith("requirements.txt"):

                dependency = parse_requirements_line(line)

            # ------------------------------------------------
            # package.json
            # ------------------------------------------------

            elif file_name.endswith("package.json"):

                dependency = parse_package_json(line)

            # ------------------------------------------------
            # package-lock.json
            # ------------------------------------------------

            elif file_name.endswith("package-lock.json"):

                dependency = parse_package_lock_line(line)

            if not dependency:
                continue

            package, version = dependency

            # ------------------------------------------------
            # Deduplicate dependency scanning
            # ------------------------------------------------

            dependency_key = (
                str(package).lower(),
                version,
                ecosystem,
            )

            if dependency_key in scanned_dependencies:
                continue

            scanned_dependencies.add(dependency_key)

            total_dependencies += 1

            # ------------------------------------------------
            # Query OSV
            # ------------------------------------------------

            vulnerabilities = query_osv(
                package,
                version,
                ecosystem,
            )

            # ------------------------------------------------
            # Remove equivalent GHSA/PYSEC records
            # ------------------------------------------------

            vulnerabilities = deduplicate_osv_vulnerabilities(vulnerabilities)

            # ------------------------------------------------
            # Process vulnerabilities
            # ------------------------------------------------

            for vulnerability in vulnerabilities:

                if not isinstance(
                    vulnerability,
                    dict,
                ):
                    continue

                affected, fixed_version = get_affected_status(
                    vulnerability,
                    version,
                )

                if not affected:
                    continue

                vulnerability_id = vulnerability.get(
                    "id",
                    "UNKNOWN",
                )

                severity = get_severity(vulnerability)

                # --------------------------------------------
                # Finding-level verdict
                # --------------------------------------------

                finding_verdict = (
                    "BLOCK"
                    if severity
                    in {
                        "CRITICAL",
                        "HIGH",
                        "MEDIUM",
                        "MODERATE",
                    }
                    else "WARN"
                )

                finding = {
                    "file": file_name,
                    "line": line_number,
                    "package": package,
                    "version": version,
                    "id": vulnerability_id,
                    "severity": severity,
                    "issue": vulnerability.get(
                        "summary",
                        "Dependency vulnerability detected.",
                    ),
                    "reason": build_reason(
                        package,
                        version,
                        vulnerability,
                    ),
                    "verdict": finding_verdict,
                }

                # --------------------------------------------
                # Detailed recommendation
                # --------------------------------------------

                if include_details:

                    if fixed_version:

                        finding["recommendation"] = (
                            f"Upgrade {package} "
                            f"from {version} to "
                            f"{fixed_version} or a newer "
                            "secure release."
                        )

                    else:

                        finding["recommendation"] = build_recommendation(
                            package,
                            version,
                            vulnerability,
                        )

                findings.append(finding)

    # ========================================================
    # FINAL SAFETY DEDUPLICATION
    # ========================================================
    #
    # This is a second protection layer.
    #
    # If two records still have the same package/version/id,
    # only one finding is retained.
    #
    # ========================================================

    unique_findings: List[Dict[str, Any]] = []

    seen_findings = set()

    for finding in findings:

        finding_key = (
            str(
                finding.get(
                    "package",
                    "",
                )
            ).lower(),
            finding.get("version"),
            str(
                finding.get(
                    "id",
                    "",
                )
            ).upper(),
        )

        if finding_key in seen_findings:
            continue

        seen_findings.add(finding_key)

        unique_findings.append(finding)

    findings = unique_findings

    # ========================================================
    # VULNERABLE DEPENDENCIES
    # ========================================================

    vulnerable_packages = {
        (
            str(
                finding.get(
                    "package",
                    "",
                )
            ).lower(),
            finding.get("version"),
        )
        for finding in findings
    }

    # ========================================================
    # SCANNER VERDICT
    # ========================================================

    verdict = "FAIL" if findings else "PASS"

    # ========================================================
    # FINAL RESULT
    # ========================================================

    return {
        "tool": "OSV",
        "status": "SUCCESS",
        "verdict": verdict,
        "total_dependencies": total_dependencies,
        "vulnerable_dependencies": len(vulnerable_packages),
        "total_vulnerabilities": len(findings),
        "findings": findings,
    }


# ============================================================
# CLI
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage: python -m src.checks.cve " "<github-pr-url>",
            file=sys.stderr,
        )

        sys.exit(1)

    pr_url = sys.argv[1]

    result = check_vulnerabilities(
        pr_url,
        include_details=True,
    )

    print(
        json.dumps(
            result,
            indent=2,
        )
    )
