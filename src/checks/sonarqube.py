import os
import sys
import json
import time
import shutil
import tempfile
import subprocess
import requests

from dotenv import load_dotenv
import src.github_client as github_client

load_dotenv()


SONAR_TOKEN = os.getenv("SONAR_TOKEN")
SONAR_ORGANIZATION = os.getenv("SONAR_ORGANIZATION", "himanidhawan4")
SONAR_PROJECT_KEY = os.getenv(
    "SONAR_PROJECT_KEY", "himanidhawan4_release-portal-security-gate-test"
)
SONAR_SCANNER_PATH = os.getenv("SONAR_SCANNER_PATH")


SONAR_API_URL = "https://sonarcloud.io/api"


# ================================================================
# FIND SONAR SCANNER
# ================================================================


def find_sonar_scanner():
    """
    Find SonarScanner either from SONAR_SCANNER_PATH
    or from the system PATH.
    """

    if SONAR_SCANNER_PATH:
        if os.path.exists(SONAR_SCANNER_PATH):
            return SONAR_SCANNER_PATH

        print(
            "Error: SONAR_SCANNER_PATH was provided but the file was not found.",
            file=sys.stderr,
        )
        return None

    scanner_names = [
        "sonar-scanner",
        "sonar-scanner.bat",
    ]

    for scanner in scanner_names:

        scanner_path = shutil.which(scanner)

        if scanner_path:
            return scanner_path

    return None


# ================================================================
# SONARCLOUD API REQUEST
# ================================================================


def sonar_request(endpoint, params=None):
    """
    Send an authenticated GET request to SonarCloud.
    """

    if not SONAR_TOKEN:
        print("Error: SONAR_TOKEN is not configured.", file=sys.stderr)
        return None

    try:

        response = requests.get(
            f"{SONAR_API_URL}{endpoint}",
            params=params,
            auth=(SONAR_TOKEN, ""),
            timeout=30,
        )

        response.raise_for_status()

        return response.json()

    except requests.RequestException as e:

        print(f"SonarCloud API error: {str(e)}", file=sys.stderr)

        return None


# ================================================================
# EXTRACT RULE INFORMATION
# ================================================================


def get_rule_details(rule_key):
    """
    Dynamically retrieve rule information from SonarCloud.

    No rule IDs are hard-coded.
    """

    data = sonar_request("/rules/show", params={"key": rule_key})

    if not data or "rule" not in data:
        return {
            "rule_name": rule_key,
            "reason": "No additional explanation available.",
            "recommendation": "Review the SonarCloud rule documentation.",
        }

    rule = data["rule"]

    rule_name = rule.get("name") or rule_key

    description_sections = rule.get("descriptionSections", [])

    reason = None
    recommendations = []

    for section in description_sections:

        section_key = section.get("key")
        content = section.get("content", "")

        if section_key == "root_cause":
            reason = clean_sonar_text(content)

        elif section_key == "how_to_fix":
            cleaned = clean_sonar_text(content)

            if cleaned:
                recommendations.append(cleaned)

    # Fallback if SonarCloud does not provide root_cause
    if not reason:

        reason = clean_sonar_text(rule.get("htmlDesc", ""))

    if not reason:
        reason = "No additional explanation available."

    if recommendations:

        recommendation = "\n\n".join(recommendations)

    else:

        recommendation = (
            "Review the SonarCloud rule guidance "
            "and modify the code according to the "
            "recommended secure practice."
        )

    return {
        "rule_name": rule_name,
        "reason": reason,
        "recommendation": recommendation,
    }


# ================================================================
# CLEAN SONARCLOUD TEXT
# ================================================================


def clean_sonar_text(text):
    """
    Remove basic HTML and unnecessary whitespace from
    SonarCloud descriptions.
    """

    if not text:
        return ""

    replacements = {
        "<p>": "",
        "</p>": "\n\n",
        "<br>": "\n",
        "<br/>": "\n",
        "<br />": "\n",
        "<code>": "",
        "</code>": "",
        "<pre>": "",
        "</pre>": "",
    }

    cleaned = text

    for old, new in replacements.items():
        cleaned = cleaned.replace(old, new)

    # Remove remaining HTML tags
    import re

    cleaned = re.sub(r"<[^>]+>", "", cleaned)

    cleaned = cleaned.replace("&nbsp;", " ")

    cleaned = cleaned.replace("&quot;", '"')

    cleaned = cleaned.replace("&lt;", "<")

    cleaned = cleaned.replace("&gt;", ">")

    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)

    cleaned = re.sub(r"[ \t]+", " ", cleaned)

    return cleaned.strip()


# ================================================================
# SHORTEN LONG TEXT
# ================================================================


def shorten_text(text, max_sentences=3):
    """
    Keep the explanation readable instead of printing
    the entire SonarCloud documentation.
    """

    if not text:
        return ""

    # Split approximately into sentences.
    import re

    sentences = re.split(r"(?<=[.!?])\s+", text.strip())

    sentences = [sentence.strip() for sentence in sentences if sentence.strip()]

    if len(sentences) <= max_sentences:
        return text.strip()

    return " ".join(sentences[:max_sentences]).strip()


# ================================================================
# WAIT FOR SONARCLOUD ANALYSIS
# ================================================================


def wait_for_analysis(task_id):
    """
    Wait until SonarCloud finishes processing the scanner task.
    """

    print("Waiting for SonarCloud analysis to complete...")

    for _ in range(60):

        data = sonar_request("/ce/task", params={"id": task_id})

        if not data:

            time.sleep(5)
            continue

        task = data.get("task", {})

        status = task.get("status")

        if status == "SUCCESS":

            print("SonarCloud analysis completed successfully.")

            return task

        if status in ("FAILED", "CANCELED"):

            print(f"SonarCloud analysis failed: {status}", file=sys.stderr)

            return None

        time.sleep(5)

    print("Error: Timed out waiting for SonarCloud analysis.", file=sys.stderr)

    return None


# ================================================================
# DISPLAY DETAILED FINDINGS
# ================================================================


def display_detailed_findings(findings):
    """
    Display SonarCloud findings in a human-readable format.
    """

    print()
    print("=" * 70)
    print("🔍 SONARCLOUD DETAILED SECURITY REPORT")
    print("=" * 70)

    if not findings:

        print()
        print("✅ No SonarCloud issues were found.")
        print()

        return

    for index, finding in enumerate(findings, start=1):

        print()
        print(f"🔴 SECURITY FINDING #{index}")
        print("-" * 70)

        print(f"📄 File          : " f"{finding.get('filename', 'Unknown')}")

        print(f"📍 Line          : " f"{finding.get('line', 'Unknown')}")

        print(f"🔑 Rule          : " f"{finding.get('rule_name', 'Unknown')}")

        print(f"⚠️ Severity      : " f"{finding.get('severity', 'Unknown')}")

        print(f"🛡️ Type          : " f"{finding.get('type', 'Unknown')}")

        print()
        print("❌ ISSUE")
        print("-" * 70)

        print(finding.get("error", "No issue description available."))

        print()
        print("💡 WHY IS THIS A PROBLEM?")
        print("-" * 70)

        reason = shorten_text(finding.get("reason", ""), max_sentences=3)

        print(reason)

        print()
        print("🔧 RECOMMENDATION")
        print("-" * 70)

        recommendation = shorten_text(
            finding.get("recommendation", ""), max_sentences=4
        )

        print(recommendation)

        print()
        print("-" * 70)

    print()
    print("=" * 70)
    print(f"📊 Total issues found: {len(findings)}")
    print("=" * 70)
    print()


# ================================================================
# DISPLAY SUMMARY
# ================================================================


def display_summary(result):
    """
    Display only the main verdict when the user does not
    want detailed explanations.
    """

    print()
    print("=" * 70)
    print("🛡️ SONARCLOUD SECURITY GATE RESULT")
    print("=" * 70)

    quality_gate = result.get("quality_gate", "UNKNOWN")

    total_issues = result.get("total_issues", 0)

    if quality_gate == "OK":

        print("✅ VERDICT       : PASS")

    else:

        print("❌ VERDICT       : FAIL")

    print(f"🚦 Quality Gate  : {quality_gate}")

    print(f"🔍 Issues        : {total_issues}")

    if result.get("findings"):

        print()
        print("Findings:")

        for finding in result["findings"]:

            print(f"  • {finding.get('filename')} " f"(line {finding.get('line')})")

            print(f"    {finding.get('error')}")

            print(f"    Severity: " f"{finding.get('severity')}")

    else:

        print()
        print("✅ No issues found.")

    print()
    print("=" * 70)
    print()


# ================================================================
# MAIN SONARCLOUD SCAN
# ================================================================


def run_sonarqube_scan(pr_url, include_details=True):
    """
    Run a universal SonarCloud PR analysis.

    PR number, source branch, target branch,
    repository and commit are obtained dynamically
    from GitHub.
    """

    if not SONAR_TOKEN:

        print("Error: SONAR_TOKEN is not configured.", file=sys.stderr)

        return {
            "tool": "SonarCloud",
            "status": "ERROR",
            "message": "SONAR_TOKEN is missing.",
        }

    # ------------------------------------------------------------
    # Fetch PR details
    # ------------------------------------------------------------

    pr_details = github_client.fetch_pr_details(pr_url)

    if not pr_details:

        return {
            "tool": "SonarCloud",
            "status": "ERROR",
            "message": "Unable to fetch GitHub PR details.",
        }

    owner = pr_details["owner"]
    repo = pr_details["repo"]
    pull_number = pr_details["pull_number"]
    head_branch = pr_details["head_branch"]
    base_branch = pr_details["base_branch"]
    head_sha = pr_details["head_sha"]
    clone_url = pr_details["clone_url"]

    print(f"PR number: {pull_number}")

    print(f"PR source branch: {head_branch}")

    print(f"PR target branch: {base_branch}")

    # ------------------------------------------------------------
    # Find SonarScanner
    # ------------------------------------------------------------

    scanner = find_sonar_scanner()

    if not scanner:

        return {
            "tool": "SonarCloud",
            "status": "ERROR",
            "message": ("SonarScanner was not found. " "Configure SONAR_SCANNER_PATH."),
        }

    # ------------------------------------------------------------
    # Temporary workspace
    # ------------------------------------------------------------

    temp_dir = tempfile.mkdtemp(prefix="release_portal_sonar_")

    try:

        repo_dir = os.path.join(temp_dir, "repository")

        print("Cloning repository...")

        clone_result = subprocess.run(
            ["git", "clone", clone_url, repo_dir], capture_output=True, text=True
        )

        if clone_result.returncode != 0:

            print(clone_result.stderr, file=sys.stderr)

            return {
                "tool": "SonarCloud",
                "status": "ERROR",
                "message": "Failed to clone repository.",
            }

        # --------------------------------------------------------
        # Checkout exact PR commit
        # --------------------------------------------------------

        print(f"Checking out PR commit: {head_sha}")

        checkout_result = subprocess.run(
            ["git", "checkout", head_sha], cwd=repo_dir, capture_output=True, text=True
        )

        if checkout_result.returncode != 0:

            print(checkout_result.stderr, file=sys.stderr)

            return {
                "tool": "SonarCloud",
                "status": "ERROR",
                "message": "Failed to checkout PR commit.",
            }

        # --------------------------------------------------------
        # Run SonarScanner
        # --------------------------------------------------------

        print("Running SonarCloud scan...")

        scanner_command = [
            scanner,
            f"-Dsonar.token={SONAR_TOKEN}",
            f"-Dsonar.organization=" f"{SONAR_ORGANIZATION}",
            f"-Dsonar.projectKey=" f"{SONAR_PROJECT_KEY}",
            f"-Dsonar.pullrequest.key=" f"{pull_number}",
            f"-Dsonar.pullrequest.branch=" f"{head_branch}",
            f"-Dsonar.pullrequest.base=" f"{base_branch}",
        ]

        scan_result = subprocess.run(
            scanner_command, cwd=repo_dir, capture_output=True, text=True
        )

        if scan_result.returncode != 0:

            print(scan_result.stdout)

            print(scan_result.stderr, file=sys.stderr)

            return {
                "tool": "SonarCloud",
                "status": "ERROR",
                "message": "SonarCloud scan failed.",
            }

        print("SonarCloud scan completed.")

        # --------------------------------------------------------
        # Extract CE task ID
        # --------------------------------------------------------

        task_id = None

        for line in (scan_result.stdout + "\n" + scan_result.stderr).splitlines():

            if "ceTaskId=" in line:

                task_id = line.split("ceTaskId=")[1].strip()

                break

        if not task_id:

            return {
                "tool": "SonarCloud",
                "status": "ERROR",
                "message": ("SonarCloud task ID was not found."),
            }

        # --------------------------------------------------------
        # Wait for analysis
        # --------------------------------------------------------

        task = wait_for_analysis(task_id)

        if not task:

            return {
                "tool": "SonarCloud",
                "status": "ERROR",
                "message": ("SonarCloud analysis did not complete."),
            }

        analysis_id = task.get("analysisId")

        # --------------------------------------------------------
        # Quality Gate
        # --------------------------------------------------------

        quality_data = sonar_request(
            "/qualitygates/project_status", params={"pullRequest": pull_number}
        )

        if not quality_data:

            return {
                "tool": "SonarCloud",
                "status": "ERROR",
                "message": ("Unable to retrieve SonarCloud " "quality gate."),
            }

        quality_gate = quality_data.get("projectStatus", {}).get("status", "UNKNOWN")

        # --------------------------------------------------------
        # Get PR issues
        # --------------------------------------------------------

        issues_data = sonar_request(
            "/issues/search",
            params={"pullRequest": pull_number, "resolved": "false", "ps": 500},
        )

        if not issues_data:

            issues = []

        else:

            issues = issues_data.get("issues", [])

        # --------------------------------------------------------
        # Build findings
        # --------------------------------------------------------

        findings = []

        for issue in issues:

            rule_key = issue.get("rule")

            rule_details = get_rule_details(rule_key)

            finding = {
                "filename": issue.get("component"),
                "line": issue.get("line"),
                "error": issue.get("message"),
                "severity": issue.get("severity"),
                "type": issue.get("type"),
                "rule_name": rule_details.get("rule_name"),
            }

            if include_details:

                finding["reason"] = rule_details.get("reason")

                finding["recommendation"] = rule_details.get("recommendation")

            findings.append(finding)

        # --------------------------------------------------------
        # Final result
        # --------------------------------------------------------

        result = {
            "tool": "SonarCloud",
            "status": "SUCCESS",
            "quality_gate": quality_gate,
            "total_issues": len(findings),
            "findings": findings,
        }

        # --------------------------------------------------------
        # Human-readable output
        # --------------------------------------------------------

        if include_details:

            display_detailed_findings(findings)

        else:

            display_summary(result)

        # JSON result remains available to main.py/frontend
        print(json.dumps(result, indent=2))

        return result

    finally:

        # --------------------------------------------------------
        # Remove temporary repository
        # --------------------------------------------------------

        shutil.rmtree(temp_dir, ignore_errors=True)


# ================================================================
# CLI
# ================================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print("Usage: python .\\src\\checks\\sonarqube.py " "<GitHub Pull Request URL>")

        sys.exit(1)

    pr_url = sys.argv[1]

    while True:

        choice = (
            input(
                "Do you have time to review detailed "
                "SonarCloud reasons and recommendations? (y/n): "
            )
            .strip()
            .lower()
        )

        if choice in ("y", "n"):
            break

        print("Please enter either y or n.")

    include_details = choice == "y"

    run_sonarqube_scan(pr_url, include_details=include_details)
