import sys
import json

from src.checks import secrets
from src.checks import iam
from src.checks import cve
from src.checks import sonarqube

# ============================================================
# HEADER
# ============================================================


def print_header():
    print("\n" + "=" * 75)
    print("                    RELEASE PORTAL SECURITY GATE")
    print("=" * 75)


# ============================================================
# RUN SECRET SCAN
# ============================================================


def run_secret_scan(pr_url):
    print("\n" + "=" * 75)
    print("🔐 RUNNING SECRET SCAN")
    print("=" * 75)

    try:
        result = secrets.check_secrets_in_pr(pr_url)

        if result is None:
            return []

        return result

    except Exception as e:
        print(f"❌ Secret scan failed: {e}")
        return []


# ============================================================
# RUN IAM SCAN
# ============================================================


def run_iam_scan(pr_url):
    print("\n" + "=" * 75)
    print("☁️ RUNNING IAM WILDCARD SCAN")
    print("=" * 75)

    try:
        result = iam.check_wildcards(pr_url)

        if result is None:
            return []

        return result

    except Exception as e:
        print(f"❌ IAM scan failed: {e}")
        return []


# ============================================================
# RUN DEPENDENCY / CVE SCAN
# ============================================================


def run_cve_scan(pr_url):
    print("\n" + "=" * 75)
    print("📦 RUNNING DEPENDENCY VULNERABILITY SCAN")
    print("=" * 75)

    try:
        # Current cve.py prints its results but does not return them.
        result = cve.check_vulnerabilities(pr_url)

        if result is None:
            return []

        return result

    except Exception as e:
        print(f"❌ Dependency scan failed: {e}")
        return []


# ============================================================
# RUN SONARCLOUD SCAN
# ============================================================


def run_sonar_scan(pr_url):
    print("\n" + "=" * 75)
    print("🔎 RUNNING SONARCLOUD ANALYSIS")
    print("=" * 75)

    try:
        # SonarCloud scanner has its own detailed-output choice.
        result = sonarqube.run_sonarqube_scan(pr_url, include_details=True)

        if result is None:
            return {}

        return result

    except Exception as e:
        print(f"❌ SonarCloud scan failed: {e}")

        return {"tool": "SonarCloud", "status": "ERROR", "error": str(e)}


# ============================================================
# COUNT FINDINGS
# ============================================================


def count_findings(result):

    if not result:
        return 0

    if isinstance(result, list):
        return len(result)

    if isinstance(result, dict):

        if "findings" in result:
            return len(result["findings"])

        if "vulnerabilities" in result:
            return len(result["vulnerabilities"])

    return 0


# ============================================================
# RISK SCORE
# ============================================================


def calculate_risk_score(secret_results, iam_results, cve_results, sonar_results):

    score = 0

    # --------------------------------------------------------
    # Secrets
    # --------------------------------------------------------

    for finding in secret_results:

        severity = str(finding.get("Severity", "")).upper()

        if severity == "CRITICAL":
            score += 10

        elif severity == "HIGH":
            score += 8

        elif severity == "MEDIUM":
            score += 5

        elif severity == "LOW":
            score += 2

        else:
            score += 1

    # --------------------------------------------------------
    # IAM
    # --------------------------------------------------------

    for finding in iam_results:
        # IAM wildcard findings are considered high risk.
        score += 8

    # --------------------------------------------------------
    # CVE
    #
    # Current cve.py does not return its findings, so this
    # section will automatically remain 0 until cve.py returns
    # its results.
    # --------------------------------------------------------

    for finding in cve_results:

        severity = str(finding.get("severity", "")).upper()

        if severity == "CRITICAL":
            score += 10

        elif severity == "HIGH":
            score += 8

        elif severity in ("MEDIUM", "MODERATE"):
            score += 5

        elif severity == "LOW":
            score += 2

        else:
            score += 1

    # --------------------------------------------------------
    # SonarCloud
    # --------------------------------------------------------

    if isinstance(sonar_results, dict):

        for finding in sonar_results.get("findings", []):

            severity = str(finding.get("severity", "")).upper()

            if severity == "BLOCKER":
                score += 10

            elif severity == "CRITICAL":
                score += 8

            elif severity == "MAJOR":
                score += 5

            elif severity == "MINOR":
                score += 2

            else:
                score += 1

        quality_gate = str(sonar_results.get("quality_gate", "")).upper()

        if quality_gate not in ("", "OK", "PASS", "PASSED"):
            score += 5

    return min(score, 100)


# ============================================================
# RISK LEVEL
# ============================================================


def get_risk_level(score):

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


def calculate_final_verdict(secret_results, iam_results, cve_results, sonar_results):

    # Any detected secret blocks the PR.
    if secret_results:
        return "BLOCK"

    # IAM wildcard findings block the PR.
    if iam_results:
        return "BLOCK"

    # Dependency vulnerabilities.
    for finding in cve_results:

        severity = str(finding.get("severity", "")).upper()

        if severity in ("CRITICAL", "HIGH", "MEDIUM", "MODERATE"):
            return "BLOCK"

    # SonarCloud.
    if isinstance(sonar_results, dict):

        if sonar_results.get("status") == "ERROR":
            return "BLOCK"

        quality_gate = str(sonar_results.get("quality_gate", "")).upper()

        if quality_gate not in ("", "OK", "PASS", "PASSED"):
            return "BLOCK"

        if sonar_results.get("findings"):
            return "BLOCK"

    return "ALLOW"


# ============================================================
# FINAL SUMMARY
# ============================================================


def print_final_summary(
    secret_results,
    iam_results,
    cve_results,
    sonar_results,
    risk_score,
    risk_level,
    final_verdict,
):

    print("\n")
    print("=" * 75)
    print("                    FINAL SECURITY DECISION")
    print("=" * 75)

    print()

    print(f"🔐 Secret Findings      : " f"{count_findings(secret_results)}")

    print(f"☁️ IAM Findings         : " f"{count_findings(iam_results)}")

    print(f"📦 Dependency Findings : " f"{count_findings(cve_results)}")

    print(f"🔎 SonarCloud Findings : " f"{count_findings(sonar_results)}")

    print()

    print(f"📊 Risk Score           : {risk_score}/100")
    print(f"⚠️ Risk Level           : {risk_level}")
    print(f"🚦 Final Verdict        : {final_verdict}")

    print()

    if final_verdict == "BLOCK":
        print("❌ Pull Request BLOCKED because " "security issues were detected.")
    else:
        print("✅ Pull Request ALLOWED. " "No blocking security issues were detected.")

    print("=" * 75)


# ============================================================
# BUILD FINAL JSON
# ============================================================


def build_final_result(
    pr_url,
    secret_results,
    iam_results,
    cve_results,
    sonar_results,
    risk_score,
    risk_level,
    final_verdict,
):

    return {
        "project": "Release Portal Security Gate",
        "pull_request": pr_url,
        "secret_scan": {
            "count": count_findings(secret_results),
            "findings": secret_results,
        },
        "iam_scan": {"count": count_findings(iam_results), "findings": iam_results},
        "dependency_scan": {
            "count": count_findings(cve_results),
            "findings": cve_results,
        },
        "sonarqube_scan": sonar_results,
        "risk_analysis": {"score": risk_score, "level": risk_level},
        "final_verdict": final_verdict,
    }


# ============================================================
# MAIN SECURITY GATE
# ============================================================


def run_security_gate(pr_url):

    print_header()

    # --------------------------------------------------------
    # Run each scanner.
    # Each scanner handles its own detailed-output question.
    # --------------------------------------------------------

    secret_results = run_secret_scan(pr_url)

    iam_results = run_iam_scan(pr_url)

    cve_results = run_cve_scan(pr_url)

    sonar_results = run_sonar_scan(pr_url)

    # --------------------------------------------------------
    # Risk analysis
    # --------------------------------------------------------

    risk_score = calculate_risk_score(
        secret_results, iam_results, cve_results, sonar_results
    )

    risk_level = get_risk_level(risk_score)

    # --------------------------------------------------------
    # Automatic final verdict
    # --------------------------------------------------------

    final_verdict = calculate_final_verdict(
        secret_results, iam_results, cve_results, sonar_results
    )

    # --------------------------------------------------------
    # Display final summary
    # --------------------------------------------------------

    print_final_summary(
        secret_results,
        iam_results,
        cve_results,
        sonar_results,
        risk_score,
        risk_level,
        final_verdict,
    )

    # --------------------------------------------------------
    # Final JSON
    # --------------------------------------------------------

    final_result = build_final_result(
        pr_url,
        secret_results,
        iam_results,
        cve_results,
        sonar_results,
        risk_score,
        risk_level,
        final_verdict,
    )

    print("\nFinal JSON Result")
    print("=================")

    print(json.dumps(final_result, indent=2))

    return final_result


# ============================================================
# PROGRAM ENTRY POINT
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage:\n"
            'python -m src.main "https://github.com/OWNER/REPOSITORY/pull/NUMBER"'
        )

        sys.exit(1)

    pr_url = sys.argv[1].strip()

    run_security_gate(pr_url)
