import os
import re
import json
import time
import shutil
import tempfile
import subprocess
import requests
import sys

from dotenv import load_dotenv

load_dotenv()


# ============================================================
# CONFIGURATION
# ============================================================

SONAR_TOKEN_ERROR = "SONAR_TOKEN is not configured."

SONAR_URL = "https://sonarcloud.io"

SONAR_SCANNER = (
    r"C:\Users\Himani Dhawan\Downloads"
    r"\sonar-scanner-cli-8.1.0.6389-windows-x64"
    r"\sonar-scanner-8.1.0.6389-windows-x64"
    r"\bin\sonar-scanner.bat"
)


# ============================================================
# IMPORT GITHUB CLIENT
# ============================================================

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

sys.path.insert(0, PROJECT_ROOT)

try:
    from src.github_client import fetch_pr_details
except ImportError:
    from github_client import fetch_pr_details


# ============================================================
# HELPER FUNCTIONS
# ============================================================


def clean_html(text):
    """
    Remove HTML tags from SonarCloud descriptions.
    """
    if not text:
        return ""

    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)

    return text.strip()


def get_project_root():
    """
    Return project root directory.
    """
    return PROJECT_ROOT


def copy_sonar_properties(workspace):
    """
    Copy sonar-project.properties from the main project
    into the temporary cloned workspace.
    """

    source = os.path.join(get_project_root(), "sonar-project.properties")

    destination = os.path.join(workspace, "sonar-project.properties")

    if not os.path.exists(source):
        raise FileNotFoundError("sonar-project.properties was not found.")

    shutil.copy2(source, destination)


def get_sonar_property(property_name):
    """
    Read a property from sonar-project.properties.
    """

    properties_file = os.path.join(get_project_root(), "sonar-project.properties")

    if not os.path.exists(properties_file):
        raise FileNotFoundError("sonar-project.properties was not found.")

    with open(properties_file, "r", encoding="utf-8") as file:

        for line in file:

            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if "=" not in line:
                continue

            key, value = line.split("=", 1)

            if key.strip() == property_name:
                return value.strip()

    return None


# ============================================================
# PREPARE PR WORKSPACE
# ============================================================


def prepare_pr_workspace(pr_url):
    """
    Clone the GitHub repository into a temporary directory
    and checkout the exact PR commit.

    Returns:
        workspace
        pr_details
    """

    pr_details = fetch_pr_details(pr_url)

    if not pr_details:
        raise RuntimeError("Unable to fetch Pull Request details from GitHub.")

    # --------------------------------------------------------
    # Repository URL
    # --------------------------------------------------------

    repo_url = (
        pr_details.get("clone_url")
        or pr_details.get("repo_url")
        or pr_details.get("html_url")
    )

    if not repo_url:
        raise RuntimeError("Repository URL could not be determined from PR details.")

    # --------------------------------------------------------
    # PR HEAD SHA
    # --------------------------------------------------------

    head_sha = (
        pr_details.get("head_sha")
        or pr_details.get("sha")
        or pr_details.get("commit_sha")
    )

    if not head_sha:
        raise RuntimeError("PR head commit SHA could not be determined.")

    # --------------------------------------------------------
    # Temporary workspace
    # --------------------------------------------------------

    workspace = tempfile.mkdtemp(prefix="sonar_pr_")

    print("Cloning repository...")

    clone_result = subprocess.run(
        ["git", "clone", repo_url, workspace], capture_output=True, text=True
    )

    if clone_result.returncode != 0:

        shutil.rmtree(workspace, ignore_errors=True)

        raise RuntimeError("Git clone failed:\n" + clone_result.stderr)

    # --------------------------------------------------------
    # Fetch exact PR commit
    # --------------------------------------------------------

    fetch_result = subprocess.run(
        ["git", "-C", workspace, "fetch", "origin", head_sha],
        capture_output=True,
        text=True,
    )

    if fetch_result.returncode != 0:

        shutil.rmtree(workspace, ignore_errors=True)

        raise RuntimeError("Unable to fetch PR commit:\n" + fetch_result.stderr)

    print(f"Checking out PR commit: {head_sha}")

    checkout_result = subprocess.run(
        ["git", "-C", workspace, "checkout", "--detach", head_sha],
        capture_output=True,
        text=True,
    )

    if checkout_result.returncode != 0:

        shutil.rmtree(workspace, ignore_errors=True)

        raise RuntimeError("Unable to checkout PR commit:\n" + checkout_result.stderr)

    # --------------------------------------------------------
    # Copy Sonar properties
    # --------------------------------------------------------

    copy_sonar_properties(workspace)

    return workspace, pr_details


# ============================================================
# PR INFORMATION
# ============================================================


def get_pr_number(pr_url, pr_details):
    """
    Get Pull Request number.
    """

    possible_keys = ["number", "pr_number", "pull_request_number"]

    for key in possible_keys:

        value = pr_details.get(key)

        if value is not None:
            return str(value)

    match = re.search(r"/pull/(\d+)", pr_url)

    if match:
        return match.group(1)

    raise RuntimeError("Pull Request number could not be determined.")


def get_pr_branch_information(pr_details):
    """
    Extract source/head branch and target/base branch
    from GitHub PR details.
    """

    head_branch = None
    base_branch = None

    # --------------------------------------------------------
    # Direct fields
    # --------------------------------------------------------

    head_branch = (
        pr_details.get("head_branch")
        or pr_details.get("source_branch")
        or pr_details.get("head_ref")
    )

    base_branch = (
        pr_details.get("base_branch")
        or pr_details.get("target_branch")
        or pr_details.get("base_ref")
    )

    # --------------------------------------------------------
    # Nested GitHub PR format
    # --------------------------------------------------------

    head = pr_details.get("head")

    if isinstance(head, dict):

        head_branch = head_branch or head.get("ref")

    base = pr_details.get("base")

    if isinstance(base, dict):

        base_branch = base_branch or base.get("ref")

    if not head_branch:
        raise RuntimeError("PR source/head branch could not be determined.")

    if not base_branch:
        raise RuntimeError("PR target/base branch could not be determined.")

    return head_branch, base_branch


# ============================================================
# RUN SONAR SCANNER
# ============================================================


def run_sonar_scan(workspace, sonar_token, pr_number, head_branch, base_branch):
    """
    Run SonarScanner as a Pull Request analysis.
    """

    if not os.path.exists(SONAR_SCANNER):

        raise FileNotFoundError(f"SonarScanner was not found at:\n{SONAR_SCANNER}")

    print("Running SonarCloud scan...")

    command = [
        SONAR_SCANNER,
        f"-Dsonar.token={sonar_token}",
        f"-Dsonar.pullrequest.key={pr_number}",
        f"-Dsonar.pullrequest.branch={head_branch}",
        f"-Dsonar.pullrequest.base={base_branch}",
    ]

    result = subprocess.run(command, cwd=workspace, capture_output=True, text=True)

    if result.returncode != 0:

        print("\nSonarScanner output:")
        print(result.stdout)

        print("\nSonarScanner error:")
        print(result.stderr)

        raise RuntimeError("SonarCloud scan failed.")

    print("SonarCloud scan completed.")

    return result.stdout


# ============================================================
# WAIT FOR SONARCLOUD ANALYSIS
# ============================================================


def wait_for_sonar_analysis(scanner_output, sonar_token, timeout=300):
    """
    Wait until SonarCloud processing finishes.

    Returns:
        analysisId
    """

    ce_task_id = None

    # --------------------------------------------------------
    # Try to find ceTaskId
    # --------------------------------------------------------

    match = re.search(r"ceTaskId[=:]\s*([a-zA-Z0-9_-]+)", scanner_output)

    if match:
        ce_task_id = match.group(1)

    # --------------------------------------------------------
    # Try task URL
    # --------------------------------------------------------

    if not ce_task_id:

        match = re.search(r"/api/ce/task\?id=([a-zA-Z0-9_-]+)", scanner_output)

        if match:
            ce_task_id = match.group(1)

    if not ce_task_id:

        raise RuntimeError("Could not find SonarCloud CE task ID.")

    print("Waiting for SonarCloud analysis to complete...")

    headers = {"Authorization": f"Bearer {sonar_token}"}

    start_time = time.time()

    while True:

        if time.time() - start_time > timeout:

            raise TimeoutError("Timed out waiting for SonarCloud analysis.")

        response = requests.get(
            f"{SONAR_URL}/api/ce/task",
            headers=headers,
            params={"id": ce_task_id},
            timeout=30,
        )

        response.raise_for_status()

        data = response.json()

        task = data.get("task", {})

        status = task.get("status")

        if status == "SUCCESS":

            analysis_id = task.get("analysisId")

            if not analysis_id:

                raise RuntimeError(
                    "SonarCloud analysis completed but analysisId was missing."
                )

            print("SonarCloud analysis completed successfully.")

            return analysis_id

        if status in ("FAILED", "CANCELED"):

            raise RuntimeError(f"SonarCloud analysis failed with status: {status}")

        time.sleep(5)


# ============================================================
# QUALITY GATE
# ============================================================


def get_quality_gate(project_key, sonar_token, organization, pull_request):
    """
    Get Quality Gate for a specific Pull Request.
    """

    headers = {"Authorization": f"Bearer {sonar_token}"}

    params = {
        "projectKey": project_key,
        "organization": organization,
        "pullRequest": str(pull_request),
    }

    response = requests.get(
        f"{SONAR_URL}/api/qualitygates/project_status",
        headers=headers,
        params=params,
        timeout=30,
    )

    if response.status_code != 200:

        print("\nSonarCloud Quality Gate API response:")
        print(response.text)
        print()

        response.raise_for_status()

    data = response.json()

    project_status = data.get("projectStatus", {})

    return project_status.get("status", "UNKNOWN")


# ============================================================
# SONARCLOUD RULE DETAILS
# ============================================================


def extract_recommendation(rule):
    """
    Dynamically extract recommendation from SonarCloud
    descriptionSections.

    No rule IDs are hard-coded.
    """

    sections = rule.get("descriptionSections", [])

    recommendations = []

    for section in sections:

        if section.get("key") != "how_to_fix":
            continue

        content = clean_html(section.get("content", ""))

        if content and content not in recommendations:

            recommendations.append(content)

    if recommendations:

        return "\n\n".join(recommendations)

    return (
        "Review the SonarCloud rule guidance and " "apply the recommended remediation."
    )


def get_sonar_rule_details(rule_key, sonar_token, organization):
    """
    Retrieve rule details dynamically from SonarCloud.
    """

    headers = {"Authorization": f"Bearer {sonar_token}"}

    response = requests.get(
        f"{SONAR_URL}/api/rules/show",
        headers=headers,
        params={"key": rule_key, "organization": organization},
        timeout=30,
    )

    if response.status_code != 200:

        return {
            "rule_name": rule_key,
            "reason": ("SonarCloud rule details could not be retrieved."),
            "recommendation": (
                "Review this issue in SonarCloud and "
                "follow the remediation guidance."
            ),
        }

    data = response.json()

    rule = data.get("rule", {})

    rule_name = rule.get("name", rule_key)

    # --------------------------------------------------------
    # Root cause = reason
    # --------------------------------------------------------

    reason = ""

    sections = rule.get("descriptionSections", [])

    for section in sections:

        if section.get("key") == "root_cause":

            reason = clean_html(section.get("content", ""))

            if reason:
                break

    # --------------------------------------------------------
    # Fallback to HTML description
    # --------------------------------------------------------

    if not reason:

        reason = clean_html(rule.get("htmlDesc", ""))

    if not reason:

        reason = (
            "SonarCloud identified a potential security "
            "or code-quality issue based on this rule."
        )

    # --------------------------------------------------------
    # Recommendation
    # --------------------------------------------------------

    recommendation = extract_recommendation(rule)

    return {"rule_name": rule_name, "reason": reason, "recommendation": recommendation}


# ============================================================
# CREATE FINDING
# ============================================================


def create_sonar_finding(issue, sonar_token, organization, include_details):
    """
    Convert SonarCloud issue into our standard finding format.
    """

    component = issue.get("component", "")

    # --------------------------------------------------------
    # Extract filename
    # --------------------------------------------------------

    if ":" in component:

        filename = component.split(":", 1)[1]

    else:

        filename = component

    # --------------------------------------------------------
    # Line number
    # --------------------------------------------------------

    text_range = issue.get("textRange")

    line_number = None

    if isinstance(text_range, dict):

        line_number = text_range.get("startLine")

    # --------------------------------------------------------
    # Basic issue information
    # --------------------------------------------------------

    rule_key = issue.get("rule", "unknown")

    message = issue.get("message", "SonarCloud issue detected.")

    severity = issue.get("severity", "UNKNOWN")

    issue_type = issue.get("type", "UNKNOWN")

    finding = {
        "filename": filename,
        "line": line_number,
        "error": message,
        "severity": severity,
        "type": issue_type,
    }

    # --------------------------------------------------------
    # Rule details
    # --------------------------------------------------------

    details = get_sonar_rule_details(rule_key, sonar_token, organization)

    finding["rule_name"] = details["rule_name"]

    finding["reason"] = details["reason"]

    # --------------------------------------------------------
    # Recommendation only when user wants details
    # --------------------------------------------------------

    if include_details:

        finding["recommendation"] = details["recommendation"]

    return finding


# ============================================================
# GET PR-SPECIFIC ISSUES
# ============================================================


def get_sonar_issues(
    project_key, sonar_token, organization, pull_request, include_details
):
    """
    Retrieve SonarCloud issues belonging specifically
    to the Pull Request.
    """

    headers = {"Authorization": f"Bearer {sonar_token}"}

    issues = []

    page = 1
    page_size = 100

    while True:

        params = {
            "componentKeys": project_key,
            "organization": organization,
            "pullRequest": str(pull_request),
            "resolved": "false",
            "p": page,
            "ps": page_size,
        }

        response = requests.get(
            f"{SONAR_URL}/api/issues/search", headers=headers, params=params, timeout=30
        )

        if response.status_code != 200:

            print("\nSonarCloud Issues API response:")
            print(response.text)
            print()

            response.raise_for_status()

        data = response.json()

        current_issues = data.get("issues", [])

        issues.extend(current_issues)

        paging = data.get("paging", {})

        total = paging.get("total", len(issues))

        if len(issues) >= total:
            break

        page += 1

    findings = []

    for issue in issues:

        finding = create_sonar_finding(
            issue, sonar_token, organization, include_details
        )

        findings.append(finding)

    return findings


# ============================================================
# MAIN SECURITY CHECK
# ============================================================


def run_sonar_security_check(pr_url, include_details):
    """
    Complete SonarCloud security check.
    """

    sonar_token = os.getenv("SONAR_TOKEN")

    if not sonar_token:

        return {"tool": "SonarCloud", "status": "ERROR", "error": SONAR_TOKEN_ERROR}

    print("\n========================================")
    print("        SONARCLOUD SECURITY SCAN")
    print("========================================\n")

    print("GitHub token loaded successfully")

    workspace = None

    try:

        # ----------------------------------------------------
        # SonarCloud project configuration
        # ----------------------------------------------------

        organization = get_sonar_property("sonar.organization")

        project_key = get_sonar_property("sonar.projectKey")

        if not organization:

            raise RuntimeError("sonar.organization is missing.")

        if not project_key:

            raise RuntimeError("sonar.projectKey is missing.")

        # ----------------------------------------------------
        # Prepare repository
        # ----------------------------------------------------

        workspace, pr_details = prepare_pr_workspace(pr_url)

        # ----------------------------------------------------
        # PR number
        # ----------------------------------------------------

        pull_request = get_pr_number(pr_url, pr_details)

        # ----------------------------------------------------
        # Branch information
        # ----------------------------------------------------

        head_branch, base_branch = get_pr_branch_information(pr_details)

        print(f"PR number: {pull_request}")

        print(f"PR source branch: {head_branch}")

        print(f"PR target branch: {base_branch}")

        # ----------------------------------------------------
        # Run SonarScanner
        # ----------------------------------------------------

        scanner_output = run_sonar_scan(
            workspace, sonar_token, pull_request, head_branch, base_branch
        )

        # ----------------------------------------------------
        # Wait for analysis
        # ----------------------------------------------------

        wait_for_sonar_analysis(scanner_output, sonar_token)

        # ----------------------------------------------------
        # Quality Gate
        # ----------------------------------------------------

        quality_gate = get_quality_gate(
            project_key, sonar_token, organization, pull_request
        )

        # ----------------------------------------------------
        # PR-specific issues
        # ----------------------------------------------------

        findings = get_sonar_issues(
            project_key, sonar_token, organization, pull_request, include_details
        )

        # ----------------------------------------------------
        # Final result
        # ----------------------------------------------------

        return {
            "tool": "SonarCloud",
            "status": "SUCCESS",
            "quality_gate": quality_gate,
            "total_issues": len(findings),
            "findings": findings,
        }

    except Exception as error:

        return {"tool": "SonarCloud", "status": "ERROR", "error": str(error)}

    finally:

        # ----------------------------------------------------
        # Delete temporary workspace
        # ----------------------------------------------------

        if workspace and os.path.exists(workspace):

            shutil.rmtree(workspace, ignore_errors=True)


# ============================================================
# COMMAND LINE INTERFACE
# ============================================================

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print("Usage:")

        print("python .\\src\\checks\\sonarqube.py " '"<GitHub Pull Request URL>"')

        sys.exit(1)

    pr_url = sys.argv[1]

    # --------------------------------------------------------
    # Ask user whether detailed recommendations are needed
    # --------------------------------------------------------

    while True:

        choice = (
            input(
                "\nDo you have time to review detailed "
                "SonarCloud reasons and recommendations? (y/n):"
            )
            .strip()
            .lower()
        )

        if choice in ("y", "n"):

            break

        print("Please enter only 'y' or 'n'.")

    include_details = choice == "y"

    # --------------------------------------------------------
    # Run scan
    # --------------------------------------------------------

    result = run_sonar_security_check(pr_url, include_details)

    # --------------------------------------------------------
    # Print result
    # --------------------------------------------------------

    print("\n========================================")

    print("             FINAL RESULT")

    print("========================================")

    print(json.dumps(result, indent=2))
