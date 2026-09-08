import sys
import json
from datetime import datetime
from src.checks import cve
from src.checks import iam
from src.checks import secrets
from src.checks import sonarqube
import src.github_client as github_client


def ask_for_details():
    """
    Ask the CLI user whether detailed findings,
    reasons and recommendations should be included.
    """
    while True:
        answer = (
            input(
                "\nDo you want to see detailed findings, "
                "reasons and recommendations? (y/n): "
            )
            .strip()
            .lower()
        )

        if answer in ("y", "yes"):
            return True

        if answer in ("n", "no"):
            return False

        print("Please enter y/yes or n/no.")


def run_secret_scan(pr_url, include_details=False):
    """Run secret scanning."""
    return secrets.check_secrets_in_pr(
        pr_url,
        include_details=include_details,
    )


def run_iam_scan(pr_url, include_details=False):
    """Run IAM wildcard scanning."""
    return iam.check_wildcards(
        pr_url,
        include_details=include_details,
    )


def run_cve_scan(pr_url, include_details=False):
    """Run dependency vulnerability scanning."""
    return cve.check_vulnerabilities(
        pr_url,
        include_details=include_details,
    )


def run_sonar_scan(pr_url, include_details=False):
    """Run SonarCloud scanning."""
    return sonarqube.run_sonarqube_scan(
        pr_url,
        include_details=include_details,
    )


def count_findings(results):
    """
    Safely count findings.
    """
    if isinstance(results, dict):
        findings = results.get("findings", [])

        if isinstance(findings, list):
            return len(findings)

        return 0

    if isinstance(results, list):
        return len(results)

    return 0


def get_findings(results):
    """Safely return findings as a list."""
    if isinstance(results, dict):
        findings = results.get("findings", [])

        if isinstance(findings, list):
            return findings

        return []

    if isinstance(results, list):
        return results

    return []


SEVERITY_POINTS = {
    "BLOCKER": 10,
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "MODERATE": 4,
    "MAJOR": 4,
    "LOW": 2,
    "MINOR": 2,
}

DIMINISHING_MULTIPLIERS = {
    1: 1.00,
    2: 0.75,
    3: 0.50,
    4: 0.35,
}


def get_multiplier(position):
    """
    Return diminishing multiplier.
    1st finding -> 1.00
    2nd finding -> 0.75
    3rd finding -> 0.50
    4th finding -> 0.35
    5th+        -> 0.20
    """
    return DIMINISHING_MULTIPLIERS.get(position, 0.20)


def normalize_finding(
    finding,
    default_severity="MEDIUM",
    category="Security",
):
    """
    Convert scanner-specific finding formats into
    one common structure.
    No source-code content is stored or displayed.
    Only file and line number are retained.
    """
    if not isinstance(finding, dict):
        return {
            "category": category,
            "file": "",
            "line": None,
            "issue": str(finding),
            "severity": default_severity,
            "reason": "",
            "recommendation": "",
            "verdict": "",
        }

    severity = (
        finding.get("severity")
        or finding.get("level")
        or finding.get("priority")
        or default_severity
    )

    severity = str(severity).upper().strip()

    file_name = (
        finding.get("file") or finding.get("filename") or finding.get("FileName") or ""
    )

    line_number = (
        finding.get("line_number")
        if finding.get("line_number") is not None
        else finding.get("line")
    )

    if line_number is None:
        line_number = finding.get("Line_Number")

    issue = (
        finding.get("issue")
        or finding.get("title")
        or finding.get("name")
        or finding.get("type")
        or finding.get("rule_name")
        or finding.get("id")
        or finding.get("summary")
        or "Security finding"
    )

    reason = (
        finding.get("reason")
        or finding.get("Importance")
        or finding.get("message")
        or finding.get("description")
        or finding.get("summary")
        or ""
    )

    recommendation = (
        finding.get("recommendation")
        or finding.get("Recommended_Action")
        or finding.get("Recommendation")
        or finding.get("solution")
        or finding.get("fix")
        or finding.get("remediation")
        or ""
    )

    normalized = dict(finding)

    normalized["category"] = category
    normalized["file"] = file_name
    normalized["line"] = line_number
    normalized["issue"] = issue
    normalized["severity"] = severity
    normalized["reason"] = reason
    normalized["recommendation"] = recommendation

    return normalized


def normalize_findings(
    findings,
    default_severity="MEDIUM",
    category="Security",
):
    """Normalize a list of findings."""
    if not isinstance(findings, list):
        return []

    return [
        normalize_finding(
            finding,
            default_severity=default_severity,
            category=category,
        )
        for finding in findings
    ]


def get_all_normalized_findings(
    secret_results,
    iam_results,
    dependency_results,
    sonar_results,
):
    """Return all findings in one normalized list."""
    findings = []

    findings.extend(
        normalize_findings(
            get_findings(secret_results),
            default_severity="CRITICAL",
            category="Secrets",
        )
    )

    findings.extend(
        normalize_findings(
            get_findings(iam_results),
            default_severity="HIGH",
            category="IAM",
        )
    )

    findings.extend(
        normalize_findings(
            get_findings(dependency_results),
            default_severity="HIGH",
            category="Dependencies",
        )
    )

    findings.extend(
        normalize_findings(
            get_findings(sonar_results),
            default_severity="HIGH",
            category="SonarCloud",
        )
    )

    return findings


def get_risk_level(score):
    """Convert numeric risk score into risk level."""
    if score <= 20:
        return "LOW"

    if score <= 40:
        return "MEDIUM"

    if score <= 70:
        return "HIGH"

    return "CRITICAL"


def get_quality_gate_status(sonar_results):
    """Safely extract SonarCloud Quality Gate status."""
    if not isinstance(sonar_results, dict):
        return "UNKNOWN"

    quality_gate = sonar_results.get("quality_gate", {})

    if isinstance(quality_gate, dict):
        return str(
            quality_gate.get(
                "status",
                "UNKNOWN",
            )
        ).upper()

    return str(quality_gate).upper()


def calculate_risk_score(
    secret_results,
    iam_results,
    dependency_results,
    sonar_results,
):
    """
    Calculate overall security risk.
    BLOCKER / CRITICAL = 10
    HIGH = 7
    MEDIUM / MODERATE = 4
    LOW = 2

    IAM wildcard findings retain their scanner severity
    for reporting but are normalized to HIGH for risk scoring.

    SonarCloud Quality Gate failure adds 5 points.

    Diminishing multipliers are applied independently
    inside each scanner category.

    Final score is capped at 100 and rounded to
    2 decimal places.
    """
    category_scores = {
        "secrets": 0.0,
        "iam": 0.0,
        "dependencies": 0.0,
        "sonarqube": 0.0,
    }

    calculation = []

    scanner_data = [
        (
            "Secrets",
            "secrets",
            secret_results,
            "CRITICAL",
        ),
        (
            "IAM",
            "iam",
            iam_results,
            "HIGH",
        ),
        (
            "Dependencies",
            "dependencies",
            dependency_results,
            "HIGH",
        ),
        (
            "SonarCloud",
            "sonarqube",
            sonar_results,
            "HIGH",
        ),
    ]

    for (
        category_name,
        category_key,
        results,
        default_severity,
    ) in scanner_data:

        findings = normalize_findings(
            get_findings(results),
            default_severity=default_severity,
            category=category_name,
        )

        for position, finding in enumerate(
            findings,
            start=1,
        ):

            severity = str(
                finding.get(
                    "severity",
                    default_severity,
                )
            ).upper()

            if category_name == "IAM":
                severity_for_score = "HIGH"
            else:
                severity_for_score = severity

            points = SEVERITY_POINTS.get(
                severity_for_score,
                SEVERITY_POINTS.get(
                    default_severity,
                    4,
                ),
            )

            multiplier = get_multiplier(position)

            contribution = round(
                points * multiplier,
                2,
            )

            category_scores[category_key] += contribution

            calculation.append(
                {
                    "category": category_name,
                    "issue": finding.get(
                        "issue",
                        "Security finding",
                    ),
                    "severity": severity,
                    "scoring_severity": severity_for_score,
                    "base_points": points,
                    "multiplier": multiplier,
                    "contribution": contribution,
                }
            )

    quality_gate_status = get_quality_gate_status(sonar_results)

    quality_gate_penalty = 0

    if quality_gate_status not in (
        "",
        "UNKNOWN",
        "OK",
        "PASSED",
        "PASS",
    ):

        quality_gate_penalty = 5

        category_scores["sonarqube"] += 5

        calculation.append(
            {
                "category": "SonarCloud",
                "issue": "Quality Gate Failure",
                "severity": "N/A",
                "scoring_severity": "N/A",
                "base_points": 5,
                "multiplier": 1.00,
                "contribution": 5,
            }
        )

    total_score = sum(category_scores.values())

    total_score = min(
        round(total_score),
        100,
    )
    risk_level = get_risk_level(total_score)

    category_scores = {
        key: round(
            value,
            2,
        )
        for key, value in category_scores.items()
    }

    methodology = {
        "severity_points": {
            "BLOCKER": 10,
            "CRITICAL": 10,
            "HIGH": 7,
            "MEDIUM": 4,
            "MODERATE": 4,
            "MAJOR": 4,
            "LOW": 2,
        },
        "diminishing_multipliers": {
            "1st finding": 1.00,
            "2nd finding": 0.75,
            "3rd finding": 0.50,
            "4th finding": 0.35,
            "5th and later": 0.20,
        },
        "iam_scoring": (
            "IAM wildcard findings retain their scanner "
            "severity for reporting but are normalized "
            "to HIGH severity for risk-score calculation."
        ),
        "quality_gate_penalty": ("SonarCloud Quality Gate failure adds 5 points."),
        "score_rounding": (
            "The final risk score is capped at 100 " "and rounded to 2 decimal places."
        ),
        "maximum_score": 100,
        "risk_thresholds": {
            "0-20": "LOW",
            "21-40": "MEDIUM",
            "41-70": "HIGH",
            "71-100": "CRITICAL",
        },
        "mandatory_block_conditions": [
            "Security scanner execution failure",
            "Any secret detected",
            "Any IAM wildcard detected",
            "Critical dependency vulnerability",
            "High dependency vulnerability",
            "Medium/Moderate dependency vulnerability",
            "SonarCloud execution failure",
            "SonarCloud Quality Gate failure",
            "Any SonarCloud finding",
        ],
    }

    return {
        "score": total_score,
        "level": risk_level,
        "category_scores": category_scores,
        "calculation": calculation,
        "quality_gate_status": quality_gate_status,
        "quality_gate_penalty": quality_gate_penalty,
        "methodology": methodology,
    }


def calculate_final_verdict(
    secret_results,
    iam_results,
    dependency_results,
    sonar_results,
):
    """
    Decide whether the release should be ALLOWED or BLOCKED.
    LOW dependency findings do not automatically block.
    """
    for results in (
        secret_results,
        iam_results,
        dependency_results,
        sonar_results,
    ):

        if isinstance(results, dict):

            status = str(
                results.get(
                    "status",
                    "",
                )
            ).upper()

            if status in (
                "ERROR",
                "FAILED",
            ):
                return "BLOCK"

    if count_findings(secret_results) > 0:
        return "BLOCK"

    if count_findings(iam_results) > 0:
        return "BLOCK"

    dependency_findings = get_findings(dependency_results)

    for finding in dependency_findings:

        normalized = normalize_finding(
            finding,
            default_severity="HIGH",
            category="Dependencies",
        )

        severity = str(normalized["severity"]).upper()

        if severity in (
            "BLOCKER",
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "MODERATE",
        ):
            return "BLOCK"

    if isinstance(
        sonar_results,
        dict,
    ):

        sonar_status = str(
            sonar_results.get(
                "status",
                "",
            )
        ).upper()

        if sonar_status in (
            "ERROR",
            "FAILED",
        ):
            return "BLOCK"

    quality_gate_status = get_quality_gate_status(sonar_results)

    if quality_gate_status not in (
        "",
        "UNKNOWN",
        "OK",
        "PASSED",
        "PASS",
    ):
        return "BLOCK"

    if count_findings(sonar_results) > 0:
        return "BLOCK"

    return "ALLOW"


def get_pr_information(pr_url):
    """
    Fetch and normalize GitHub PR information.
    """
    try:

        pr_data = github_client.fetch_pr_details(pr_url)

        if not isinstance(
            pr_data,
            dict,
        ):

            return {
                "status": "ERROR",
                "error": "Invalid GitHub API response.",
            }

        owner = pr_data.get(
            "owner",
            "Unknown",
        )

        repo = pr_data.get(
            "repo",
            "Unknown",
        )

        pull_number = pr_data.get("pull_number")

        title = pr_data.get(
            "title",
            "Unknown",
        )

        state = pr_data.get(
            "state",
            "unknown",
        )

        head_branch = pr_data.get("head_branch")

        base_branch = pr_data.get("base_branch")

        changed_files_count = pr_data.get(
            "changed_files_count",
            0,
        )

        additions = pr_data.get(
            "additions",
            0,
        )

        deletions = pr_data.get(
            "deletions",
            0,
        )

        commits = pr_data.get(
            "commits",
            0,
        )

        repository = (
            f"{owner}/{repo}" if owner != "Unknown" and repo != "Unknown" else "Unknown"
        )

        return {
            "repository": repository,
            "owner": owner,
            "repo": repo,
            "title": title,
            "number": pull_number,
            "state": state,
            "source_branch": head_branch,
            "target_branch": base_branch,
            "commits": commits,
            "files_changed": changed_files_count,
            "additions": additions,
            "deletions": deletions,
            "head_sha": pr_data.get("head_sha"),
            "url": pr_url,
            "status": "SUCCESS",
        }

    except Exception as e:

        return {
            "status": "ERROR",
            "error": str(e),
        }


def get_scanner_status(results):
    """Return scanner status safely."""
    if isinstance(
        results,
        dict,
    ):

        return str(
            results.get(
                "status",
                "UNKNOWN",
            )
        ).upper()

    if isinstance(
        results,
        list,
    ):

        return "SUCCESS"

    return "UNKNOWN"


def get_vulnerable_dependency_count(
    dependency_results,
):
    """
    Return the number of unique vulnerable packages.
    This is different from the number of
    vulnerability findings.
    """
    if not isinstance(
        dependency_results,
        dict,
    ):

        return 0

    vulnerable_dependencies = dependency_results.get("vulnerable_dependencies")

    if vulnerable_dependencies is not None:

        try:

            return int(vulnerable_dependencies)

        except (
            TypeError,
            ValueError,
        ):

            pass

    findings = get_findings(dependency_results)

    vulnerable_packages = set()

    for finding in findings:

        if not isinstance(
            finding,
            dict,
        ):

            continue

        package = finding.get("package")

        version = finding.get("version")

        if package:

            vulnerable_packages.add(
                (
                    str(package).lower().strip(),
                    (str(version).strip() if version is not None else ""),
                )
            )

    return len(vulnerable_packages)


def build_scan_information(
    secret_results,
    iam_results,
    dependency_results,
    sonar_results,
):
    """Build scan summary."""
    dependency_findings_count = count_findings(dependency_results)

    vulnerable_dependency_count = get_vulnerable_dependency_count(dependency_results)

    return {
        "secret_scan": {
            "status": get_scanner_status(secret_results),
            "findings": count_findings(secret_results),
        },
        "iam_scan": {
            "status": get_scanner_status(iam_results),
            "findings": count_findings(iam_results),
        },
        "dependency_scan": {
            "status": get_scanner_status(dependency_results),
            "findings": dependency_findings_count,
            "vulnerable_dependencies": (vulnerable_dependency_count),
            "vulnerabilities": (dependency_findings_count),
        },
        "sonarqube_scan": {
            "status": get_scanner_status(sonar_results),
            "quality_gate": get_quality_gate_status(sonar_results),
            "findings": count_findings(sonar_results),
            "project_key": sonar_results.get("project_key", "N/A"),
        },
    }


def build_change_information(
    pr_information,
):
    """Build PR change summary."""
    if not isinstance(
        pr_information,
        dict,
    ):

        return {}

    return {
        "files_changed": pr_information.get(
            "files_changed",
            0,
        ),
        "additions": pr_information.get(
            "additions",
            0,
        ),
        "deletions": pr_information.get(
            "deletions",
            0,
        ),
        "commits": pr_information.get(
            "commits",
            0,
        ),
        "source_branch": pr_information.get("source_branch"),
        "target_branch": pr_information.get("target_branch"),
    }


def compact_finding_for_report(
    finding,
    include_details=False,
):
    """
    Prepare a finding for the final report.
    No source-code line/content is returned.
    """
    normalized = normalize_finding(finding)

    compact = {
        "file": normalized.get(
            "file",
            "",
        ),
        "line": normalized.get("line"),
        "issue": normalized.get(
            "issue",
            "Security finding",
        ),
        "severity": normalized.get(
            "severity",
            "UNKNOWN",
        ),
        "reason": normalized.get(
            "reason",
            "",
        ),
        "verdict": normalized.get(
            "verdict",
            "",
        ),
    }

    if include_details:

        compact["recommendation"] = normalized.get(
            "recommendation",
            "",
        )

    if normalized.get("id"):

        compact["id"] = normalized.get("id")

    if normalized.get("package"):

        compact["package"] = normalized.get("package")

    if normalized.get("version"):

        compact["version"] = normalized.get("version")

    if normalized.get("rule_name"):

        compact["rule_name"] = normalized.get("rule_name")

    return compact


def prepare_scan_for_report(
    results,
    include_details=False,
):
    """Normalize scanner findings for Flask/CLI output."""
    if isinstance(
        results,
        list,
    ):

        return {
            "status": "SUCCESS",
            "findings": [
                compact_finding_for_report(
                    finding,
                    include_details=include_details,
                )
                for finding in results
            ],
        }

    if not isinstance(
        results,
        dict,
    ):

        return {
            "status": "ERROR",
            "findings": [],
            "error": ("Scanner returned invalid data."),
        }

    prepared = dict(results)

    findings = results.get(
        "findings",
        [],
    )

    prepared["findings"] = [
        compact_finding_for_report(
            finding,
            include_details=include_details,
        )
        for finding in findings
    ]

    return prepared


def run_security_gate(
    pr_url,
    include_details=None,
):
    """
    Main security gate controller.
    include_details=True:
        Detailed reasons and recommendations.

    include_details=False:
        Findings and reasons.

    include_details=None:
        Ask the CLI user.

    Flask should explicitly pass True or False.
    """
    if include_details is None:
        include_details = ask_for_details()

    include_details = bool(include_details)

    scan_started = datetime.now()

    pr_information = get_pr_information(pr_url)

    try:

        secret_results = run_secret_scan(
            pr_url,
            include_details=include_details,
        )

        if secret_results is None:

            secret_results = {
                "status": "ERROR",
                "findings": [],
                "error": ("Secret scanner returned no result."),
            }

    except Exception as e:

        secret_results = {
            "status": "ERROR",
            "findings": [],
            "error": str(e),
        }

    try:

        iam_results = run_iam_scan(
            pr_url,
            include_details=include_details,
        )

        if iam_results is None:

            iam_results = {
                "status": "ERROR",
                "findings": [],
                "error": ("IAM scanner returned no result."),
            }

    except Exception as e:

        iam_results = {
            "status": "ERROR",
            "findings": [],
            "error": str(e),
        }

    try:

        dependency_results = run_cve_scan(
            pr_url,
            include_details=include_details,
        )

        if dependency_results is None:

            dependency_results = {
                "status": "ERROR",
                "findings": [],
                "error": ("Dependency scanner returned no result."),
            }

    except Exception as e:

        dependency_results = {
            "status": "ERROR",
            "findings": [],
            "error": str(e),
        }

    try:

        sonar_results = run_sonar_scan(
            pr_url,
            include_details=include_details,
        )

        if sonar_results is None:

            sonar_results = {
                "tool": "SonarCloud",
                "status": "ERROR",
                "quality_gate": {"status": "ERROR"},
                "total_issues": 0,
                "findings": [],
                "error": ("SonarCloud scanner returned no result."),
            }

    except Exception as e:

        sonar_results = {
            "tool": "SonarCloud",
            "status": "ERROR",
            "quality_gate": {"status": "ERROR"},
            "total_issues": 0,
            "findings": [],
            "error": str(e),
        }

    risk_analysis = calculate_risk_score(
        secret_results,
        iam_results,
        dependency_results,
        sonar_results,
    )

    final_verdict = calculate_final_verdict(
        secret_results,
        iam_results,
        dependency_results,
        sonar_results,
    )

    scan_ended = datetime.now()

    duration_seconds = round(
        (scan_ended - scan_started).total_seconds(),
        2,
    )

    report = {
        "timestamp": scan_started.isoformat(),
        "duration_seconds": duration_seconds,
        "verdict": final_verdict,
        "risk_analysis": risk_analysis,
        "pr_information": pr_information,
        "change_information": build_change_information(pr_information),
        "scan_summary": build_scan_information(
            secret_results,
            iam_results,
            dependency_results,
            sonar_results,
        ),
        "scans": {
            "secrets": prepare_scan_for_report(
                secret_results,
                include_details=include_details,
            ),
            "iam": prepare_scan_for_report(
                iam_results,
                include_details=include_details,
            ),
            "dependencies": prepare_scan_for_report(
                dependency_results,
                include_details=include_details,
            ),
            "sonarqube": prepare_scan_for_report(
                sonar_results,
                include_details=include_details,
            ),
        },
    }

    return report


if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage: python -m src.main <github-pr-url>",
            file=sys.stderr,
        )

        sys.exit(1)

    pr_url = sys.argv[1]

    try:

        report = run_security_gate(pr_url)

        print("\nRELEASE PORTAL SECURITY GATE")

        print(
            json.dumps(
                report,
                indent=2,
            )
        )

    except KeyboardInterrupt:

        print(
            "\nScan cancelled by user.",
            file=sys.stderr,
        )

        sys.exit(1)

    except Exception as e:

        print(
            f"\nSecurity gate failed: {e}",
            file=sys.stderr,
        )

        sys.exit(1)
