import json

from src.checks import secrets
from src.checks import iam
from src.checks import cve
from src.checks import sonarqube


# ============================================================
# USER PREFERENCE
# ============================================================

def ask_for_details():
    """
    Ask the user whether they want importance/reasons/
    recommendations in the final result.
    """

    while True:
        choice = input(
            "\nDo you want importance, reasons and recommendations "
            "along with the final verdict? (y/n): "
        ).strip().lower()

        if choice == "y":
            return True

        if choice == "n":
            return False

        print("Please enter only 'y' or 'n'.")


# ============================================================
# SECURITY SCANNERS
# ============================================================

def run_secret_scan(pr_url, include_details=False):
    """
    Run secret scanning on the Pull Request.
    """
    return secrets.check_secrets_in_pr(
        pr_url,
        include_details=include_details
    )


def run_iam_scan(pr_url, include_details=False):
    """
    Run IAM wildcard scanning on the Pull Request.
    """
    return iam.check_wildcards(
        pr_url,
        include_details=include_details
    )


def run_cve_scan(pr_url, include_details=False):
    """
    Run dependency vulnerability scanning using OSV.
    """
    return cve.check_vulnerabilities(
        pr_url,
        include_details=include_details
    )


def run_sonar_scan(pr_url, include_details=False):
    """
    Run SonarCloud analysis.
    """
    return sonarqube.run_sonarqube_scan(
        pr_url,
        include_details=include_details
    )


# ============================================================
# FINDING COUNTERS
# ============================================================

def count_findings(results):
    """
    Safely count findings returned by a scanner.

    Supports:
        list
        dictionary containing 'findings'
        dictionary containing 'total_issues'
    """

    if isinstance(results, list):
        return len(results)

    if isinstance(results, dict):

        if isinstance(results.get("findings"), list):
            return len(results["findings"])

        if isinstance(results.get("total_issues"), int):
            return results["total_issues"]

    return 0


# ============================================================
# RISK SCORE
# ============================================================

def calculate_risk_score(
    secret_results,
    iam_results,
    dependency_results,
    sonar_results
):
    """
    Calculate overall risk score.

    Maximum score = 100
    """

    score = 0

    # --------------------------------------------------------
    # SECRET SCAN
    # --------------------------------------------------------

    secret_findings = []

    if isinstance(secret_results, list):
        secret_findings = secret_results

    elif isinstance(secret_results, dict):
        secret_findings = secret_results.get("findings", [])

    for finding in secret_findings:

        severity = str(
            finding.get("Severity", finding.get("severity", ""))
        ).upper()

        if severity == "CRITICAL":
            score += 10

        elif severity == "HIGH":
            score += 8

        elif severity == "MEDIUM":
            score += 5

        elif severity == "LOW":
            score += 2

    # --------------------------------------------------------
    # IAM SCAN
    # --------------------------------------------------------

    iam_findings = []

    if isinstance(iam_results, list):
        iam_findings = iam_results

    elif isinstance(iam_results, dict):
        iam_findings = iam_results.get("findings", [])

    for _ in iam_findings:
        score += 8

    # --------------------------------------------------------
    # DEPENDENCY / CVE SCAN
    # --------------------------------------------------------

    dependency_findings = []

    if isinstance(dependency_results, list):
        dependency_findings = dependency_results

    elif isinstance(dependency_results, dict):
        dependency_findings = dependency_results.get("findings", [])

    for finding in dependency_findings:

        severity = str(
            finding.get(
                "severity",
                finding.get("Severity", "")
            )
        ).upper()

        if severity == "CRITICAL":
            score += 10

        elif severity == "HIGH":
            score += 8

        elif severity in ("MEDIUM", "MODERATE"):
            score += 5

        elif severity == "LOW":
            score += 2

    # --------------------------------------------------------
    # SONARCLOUD
    # --------------------------------------------------------

    if isinstance(sonar_results, dict):

        # Sonar issues
        sonar_findings = sonar_results.get("findings", [])

        if isinstance(sonar_findings, list):

            for finding in sonar_findings:

                severity = str(
                    finding.get(
                        "severity",
                        finding.get("Severity", "")
                    )
                ).upper()

                if severity == "BLOCKER":
                    score += 10

                elif severity == "CRITICAL":
                    score += 8

                elif severity == "MAJOR":
                    score += 5

                elif severity == "MINOR":
                    score += 2

        # Quality Gate
        quality_gate = sonar_results.get("quality_gate", {})

        if isinstance(quality_gate, dict):

            gate_status = str(
                quality_gate.get("status", "")
            ).upper()

            if gate_status and gate_status != "OK":
                score += 5

        elif isinstance(quality_gate, str):

            if quality_gate.upper() != "OK":
                score += 5

    # Never allow score above 100
    return min(score, 100)


# ============================================================
# RISK LEVEL
# ============================================================

def get_risk_level(score):
    """
    Convert risk score into a risk level.
    """

    if score == 0:
        return "LOW"

    elif score <= 20:
        return "MEDIUM"

    elif score <= 50:
        return "HIGH"

    else:
        return "CRITICAL"


# ============================================================
# FINAL VERDICT
# ============================================================

def calculate_final_verdict(
    secret_results,
    iam_results,
    dependency_results,
    sonar_results
):
    """
    Decide whether the Pull Request should be ALLOWED or BLOCKED.
    """

    # --------------------------------------------------------
    # SECRET FINDINGS
    # --------------------------------------------------------

    if count_findings(secret_results) > 0:
        return "BLOCK"

    # --------------------------------------------------------
    # IAM FINDINGS
    # --------------------------------------------------------

    if count_findings(iam_results) > 0:
        return "BLOCK"

    # --------------------------------------------------------
    # DEPENDENCY FINDINGS
    # --------------------------------------------------------

    dependency_findings = []

    if isinstance(dependency_results, list):
        dependency_findings = dependency_results

    elif isinstance(dependency_results, dict):
        dependency_findings = dependency_results.get(
            "findings",
            []
        )

    for finding in dependency_findings:

        severity = str(
            finding.get(
                "severity",
                finding.get("Severity", "")
            )
        ).upper()

        if severity in (
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "MODERATE"
        ):
            return "BLOCK"

    # --------------------------------------------------------
    # SONARCLOUD
    # --------------------------------------------------------

    if isinstance(sonar_results, dict):

        status = str(
            sonar_results.get("status", "")
        ).upper()

        if status in ("ERROR", "FAILED", "FAIL"):
            return "BLOCK"

        quality_gate = sonar_results.get(
            "quality_gate",
            {}
        )

        if isinstance(quality_gate, dict):

            gate_status = str(
                quality_gate.get("status", "")
            ).upper()

            if gate_status and gate_status != "OK":
                return "BLOCK"

        elif isinstance(quality_gate, str):

            if quality_gate.upper() != "OK":
                return "BLOCK"

        sonar_findings = sonar_results.get(
            "findings",
            []
        )

        if isinstance(sonar_findings, list):
            if len(sonar_findings) > 0:
                return "BLOCK"

    # --------------------------------------------------------
    # EVERYTHING PASSED
    # --------------------------------------------------------

    return "ALLOW"


# ============================================================
# BUILD FINAL RESULT
# ============================================================

def build_final_result(
    pr_url,
    secret_results,
    iam_results,
    dependency_results,
    sonar_results,
    risk_score,
    risk_level,
    final_verdict
):
    """
    Create the final JSON-compatible result.
    """

    return {
        "project": "Release Portal Security Gate",

        "pull_request": pr_url,

        "secret_scan": {
            "count": count_findings(secret_results),
            "findings": (
                secret_results
                if isinstance(secret_results, list)
                else secret_results.get("findings", [])
                if isinstance(secret_results, dict)
                else []
            )
        },

        "iam_scan": {
            "count": count_findings(iam_results),
            "findings": (
                iam_results
                if isinstance(iam_results, list)
                else iam_results.get("findings", [])
                if isinstance(iam_results, dict)
                else []
            )
        },

        "dependency_scan": {
            "count": count_findings(dependency_results),
            "findings": (
                dependency_results
                if isinstance(dependency_results, list)
                else dependency_results.get("findings", [])
                if isinstance(dependency_results, dict)
                else []
            )
        },

        "sonarqube_scan": (
            sonar_results
            if isinstance(sonar_results, dict)
            else {
                "findings": sonar_results
            }
        ),

        "risk_analysis": {
            "score": risk_score,
            "level": risk_level
        },

        "final_verdict": final_verdict
    }


# ============================================================
# MAIN SECURITY GATE
# ============================================================

def run_security_gate(pr_url, include_details=None):
    """
    Main security gate.

    If include_details is None:
        Ask the user.

    If include_details is True:
        Show importance/reasons/recommendations.

    If include_details is False:
        Show only the main findings/verdict information.
    """

    # --------------------------------------------------------
    # ASK USER ONLY ONCE
    # --------------------------------------------------------

    if include_details is None:
        include_details = ask_for_details()

    print("\n" + "=" * 75)
    print("                 RELEASE PORTAL SECURITY GATE")
    print("=" * 75)

    print(f"\nPull Request: {pr_url}")

    if include_details:
        print("Details: ENABLED")
    else:
        print("Details: DISABLED")

    # --------------------------------------------------------
    # SECRET SCAN
    # --------------------------------------------------------

    print("\n" + "=" * 75)
    print("🔐 RUNNING SECRET SCAN")
    print("=" * 75)

    try:
        secret_results = run_secret_scan(
            pr_url,
            include_details=include_details
        )
    except Exception as e:
        print(f"❌ Secret scan failed: {e}")
        secret_results = []

    # --------------------------------------------------------
    # IAM SCAN
    # --------------------------------------------------------

    print("\n" + "=" * 75)
    print("🔑 RUNNING IAM WILDCARD SCAN")
    print("=" * 75)

    try:
        iam_results = run_iam_scan(
            pr_url,
            include_details=include_details
        )
    except Exception as e:
        print(f"❌ IAM scan failed: {e}")
        iam_results = []

    # --------------------------------------------------------
    # DEPENDENCY / CVE SCAN
    # --------------------------------------------------------

    print("\n" + "=" * 75)
    print("📦 RUNNING DEPENDENCY VULNERABILITY SCAN")
    print("=" * 75)

    try:
        dependency_results = run_cve_scan(
            pr_url,
            include_details=include_details
        )
    except Exception as e:
        print(f"❌ Dependency scan failed: {e}")
        dependency_results = []

    # --------------------------------------------------------
    # SONARCLOUD
    # --------------------------------------------------------

    print("\n" + "=" * 75)
    print("📊 RUNNING SONARCLOUD SCAN")
    print("=" * 75)

    try:
        sonar_results = run_sonar_scan(
            pr_url,
            include_details=include_details
        )
    except Exception as e:
        print(f"❌ SonarCloud scan failed: {e}")
        sonar_results = {
            "tool": "SonarCloud",
            "status": "ERROR",
            "quality_gate": {
                "status": "ERROR"
            },
            "total_issues": 0,
            "findings": [],
            "error": str(e)
        }

    # --------------------------------------------------------
    # RISK SCORE
    # --------------------------------------------------------

    risk_score = calculate_risk_score(
        secret_results,
        iam_results,
        dependency_results,
        sonar_results
    )

    risk_level = get_risk_level(risk_score)

    # --------------------------------------------------------
    # FINAL VERDICT
    # --------------------------------------------------------

    final_verdict = calculate_final_verdict(
        secret_results,
        iam_results,
        dependency_results,
        sonar_results
    )

    # --------------------------------------------------------
    # BUILD RESULT
    # --------------------------------------------------------

    final_result = build_final_result(
        pr_url,
        secret_results,
        iam_results,
        dependency_results,
        sonar_results,
        risk_score,
        risk_level,
        final_verdict
    )

    # --------------------------------------------------------
    # DISPLAY FINAL RESULT
    # --------------------------------------------------------

    print("\n" + "=" * 75)
    print("                    FINAL SECURITY VERDICT")
    print("=" * 75)

    print(f"\nRisk Score : {risk_score}/100")
    print(f"Risk Level : {risk_level}")
    print(f"Verdict    : {final_verdict}")

    print("\n" + "=" * 75)
    print("                    FINAL JSON RESULT")
    print("=" * 75)

    print(
        json.dumps(
            final_result,
            indent=4
        )
    )

    return final_result


# ============================================================
# COMMAND-LINE ENTRY POINT
# ============================================================

if __name__ == "__main__":

    import sys

    if len(sys.argv) != 2:

        print(
            "\nUsage:"
        )

        print(
            'python -m src.main "https://github.com/OWNER/REPO/pull/NUMBER"'
        )

        sys.exit(1)

    pr_url = sys.argv[1]

    # include_details=None means:
    # ASK THE USER whether they want details.
    run_security_gate(
        pr_url,
        include_details=None
    )