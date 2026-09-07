import os
import sys
import json
import time
import shutil
import tempfile
import subprocess
import re
import html
from pathlib import Path

import requests
from dotenv import load_dotenv

# =========================================================
# MAKE IMPORTS WORK IN BOTH MODES
# =========================================================
#
# This allows the file to be run as:
#
# python -m src.checks.sonarqube "<PR URL>"
#
# OR:
#
# python .\src\checks\sonarqube.py "<PR URL>"
#
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import src.github_client as github_client

# =========================================================
# LOAD ENVIRONMENT VARIABLES
# =========================================================

load_dotenv()


SONAR_HOST = "https://sonarcloud.io"

SONAR_ORGANIZATION = (os.getenv("SONAR_ORGANIZATION") or "").strip()

SONAR_PROJECT_KEY = (os.getenv("SONAR_PROJECT_KEY") or "").strip()

SONAR_TOKEN = (os.getenv("SONAR_TOKEN") or "").strip()

SONAR_SCANNER_PATH = (os.getenv("SONAR_SCANNER_PATH") or "").strip()


# =========================================================
# FIND SONARSCANNER
# =========================================================


def find_sonar_scanner():
    """
    Find SonarScanner using:

    1. SONAR_SCANNER_PATH from .env
    2. sonar-scanner from PATH
    3. sonar-scanner.bat from PATH
    """

    if SONAR_SCANNER_PATH:

        if os.path.exists(SONAR_SCANNER_PATH):
            return SONAR_SCANNER_PATH

    scanner = shutil.which("sonar-scanner")

    if scanner:
        return scanner

    scanner_bat = shutil.which("sonar-scanner.bat")

    if scanner_bat:
        return scanner_bat

    return None


# =========================================================
# SONARCLOUD API REQUEST
# =========================================================


def sonar_request(endpoint, params=None):
    """
    Send authenticated GET request to SonarCloud.

    The organization is automatically added to every
    SonarCloud API request.
    """

    if not SONAR_TOKEN:

        print(
            "Error: SONAR_TOKEN is not configured.",
            file=sys.stderr,
        )

        return None

    if not SONAR_ORGANIZATION:

        print(
            "Error: SONAR_ORGANIZATION is not configured.",
            file=sys.stderr,
        )

        return None

    url = f"{SONAR_HOST}{endpoint}"

    # Make a copy so the caller's dictionary is not modified.
    request_params = dict(params or {})

    # -----------------------------------------------------
    # IMPORTANT:
    # SonarCloud requires organization for the APIs used
    # by this project.
    # -----------------------------------------------------

    request_params["organization"] = SONAR_ORGANIZATION

    try:

        response = requests.get(
            url,
            params=request_params,
            auth=(SONAR_TOKEN, ""),
            timeout=30,
        )

    except requests.RequestException as e:

        print(
            f"Error connecting to SonarCloud: " f"{str(e)}",
            file=sys.stderr,
        )

        return None

    if response.status_code != 200:

        print(
            f"SonarCloud API error " f"{response.status_code}: " f"{response.text}",
            file=sys.stderr,
        )

        return None

    try:

        return response.json()

    except ValueError:

        print(
            "Error: SonarCloud returned invalid JSON.",
            file=sys.stderr,
        )

        return None


# =========================================================
# CLEAN SONARCLOUD TEXT
# =========================================================


def clean_sonar_text(text):
    """
    Convert SonarCloud HTML descriptions into readable text.
    """

    if not text:
        return ""

    text = html.unescape(str(text))

    # Convert HTML line breaks to spaces.
    text = re.sub(
        r"<br\s*/?>",
        " ",
        text,
        flags=re.IGNORECASE,
    )

    # Remove HTML tags.
    text = re.sub(
        r"<[^>]+>",
        " ",
        text,
    )

    # Normalize whitespace.
    text = re.sub(
        r"\s+",
        " ",
        text,
    )

    return text.strip()


# =========================================================
# SHORTEN LONG TEXT
# =========================================================


def shorten_text(
    text,
    max_sentences=3,
    max_length=700,
):
    """
    Make SonarCloud explanations easier to read.
    """

    if not text:

        return "No detailed explanation available."

    text = clean_sonar_text(text)

    # Split approximately by sentences.
    sentences = re.split(
        r"(?<=[.!?])\s+",
        text,
    )

    selected = sentences[:max_sentences]

    result = " ".join(selected).strip()

    if len(result) > max_length:

        result = result[:max_length].rsplit(" ", 1)[0] + "..."

    return result


# =========================================================
# GET DYNAMIC SONARCLOUD RULE DETAILS
# =========================================================


def get_rule_details(rule_key):
    """
    Dynamically retrieve:

    - Rule name
    - Reason
    - Recommendation

    No SonarCloud rule IDs are hard-coded.
    """

    data = sonar_request(
        "/api/rules/show",
        params={
            "key": rule_key,
        },
    )

    if not data:

        return {
            "rule_name": rule_key,
            "reason": "Detailed reason unavailable.",
            "recommendation": "Review the SonarCloud " "rule documentation.",
        }

    rule = data.get(
        "rule",
        {},
    )

    rule_name = rule.get("name") or rule_key

    description_sections = rule.get(
        "descriptionSections",
        [],
    )

    root_cause = ""

    recommendations = []

    # -----------------------------------------------------
    # Extract structured rule information
    # -----------------------------------------------------

    for section in description_sections:

        section_key = section.get(
            "key",
            "",
        )

        content = section.get(
            "content",
            "",
        )

        content = clean_sonar_text(content)

        if section_key == "root_cause":

            root_cause = content

        elif section_key == "how_to_fix":

            if content:

                recommendations.append(content)

    # -----------------------------------------------------
    # Fallback for reason
    # -----------------------------------------------------

    if not root_cause:

        for section in description_sections:

            content = clean_sonar_text(
                section.get(
                    "content",
                    "",
                )
            )

            if content:

                root_cause = content

                break

    # -----------------------------------------------------
    # Another fallback
    # -----------------------------------------------------

    if not root_cause:

        html_description = rule.get(
            "htmlDesc",
            "",
        )

        root_cause = clean_sonar_text(html_description)

    # -----------------------------------------------------
    # Build recommendation
    # -----------------------------------------------------

    recommendation = "\n\n".join(recommendations)

    if not recommendation:

        recommendation = (
            "Review the SonarCloud rule "
            "and modify the code according "
            "to the recommended secure practice."
        )

    return {
        "rule_name": rule_name,
        "reason": root_cause,
        "recommendation": recommendation,
    }


# =========================================================
# WAIT FOR SONARCLOUD ANALYSIS
# =========================================================


def wait_for_analysis(
    task_id,
    max_wait=300,
):
    """
    Poll SonarCloud until the analysis finishes.
    """

    print("Waiting for SonarCloud analysis " "to complete...")

    start_time = time.time()

    while True:

        if time.time() - start_time > max_wait:

            print(
                "Error: SonarCloud " "analysis timed out.",
                file=sys.stderr,
            )

            return None

        data = sonar_request(
            "/api/ce/task",
            params={
                "id": task_id,
            },
        )

        if not data:

            return None

        task = data.get(
            "task",
            {},
        )

        status = task.get("status")

        if status == "SUCCESS":

            print("SonarCloud analysis " "completed successfully.")

            return task

        if status in (
            "FAILED",
            "CANCELED",
        ):

            print(
                f"SonarCloud analysis ended " f"with status: {status}",
                file=sys.stderr,
            )

            return None

        time.sleep(5)


# =========================================================
# DISPLAY DETAILED FINDINGS
# =========================================================


def display_detailed_findings(findings):
    """
    Display detailed human-readable
    SonarCloud security report.
    """

    print()

    print("=" * 70)

    print("🔍 SONARCLOUD DETAILED SECURITY REPORT")

    print("=" * 70)

    if not findings:

        print()

        print("✅ No SonarCloud security issues found.")

        print("=" * 70)

        return

    for index, finding in enumerate(
        findings,
        start=1,
    ):

        print()

        print(f"🔴 SECURITY FINDING #{index}")

        print("-" * 70)

        print(f"📄 File          : " f"{finding.get('filename', 'Unknown')}")

        print(f"📍 Line          : " f"{finding.get('line', 'Unknown')}")

        print(f"🔑 Rule          : " f"{finding.get('rule_name', 'Unknown')}")

        print(f"⚠️ Severity      : " f"{finding.get('severity', 'Unknown')}")

        print(f"🛡️ Type          : " f"{finding.get('type', 'Unknown')}")

        # -------------------------------------------------
        # Issue
        # -------------------------------------------------

        print()

        print("❌ ISSUE")

        print("-" * 70)

        print(
            finding.get(
                "error",
                "No issue description available.",
            )
        )

        # -------------------------------------------------
        # Reason
        # -------------------------------------------------

        print()

        print("💡 WHY IS THIS A PROBLEM?")

        print("-" * 70)

        print(
            shorten_text(
                finding.get(
                    "reason",
                    "",
                ),
                max_sentences=3,
                max_length=700,
            )
        )

        # -------------------------------------------------
        # Recommendation
        # -------------------------------------------------

        print()

        print("🔧 RECOMMENDATION")

        print("-" * 70)

        print(
            shorten_text(
                finding.get(
                    "recommendation",
                    "",
                ),
                max_sentences=4,
                max_length=900,
            )
        )

        print()

        print("-" * 70)

    print()

    print(f"📊 Total issues found: " f"{len(findings)}")

    print("=" * 70)


# =========================================================
# DISPLAY SHORT SUMMARY
# =========================================================


def display_summary(result):
    """
    Display concise SonarCloud result.
    """

    quality_gate = result.get(
        "quality_gate",
        "UNKNOWN",
    )

    total_issues = result.get(
        "total_issues",
        0,
    )

    if quality_gate == "OK":

        verdict = "PASS"

        verdict_icon = "✅"

    else:

        verdict = "FAIL"

        verdict_icon = "❌"

    print()

    print("=" * 75)

    print("🛡️ SONARCLOUD SECURITY GATE RESULT")

    print("=" * 75)

    print()

    print(f"{verdict_icon} VERDICT       : " f"{verdict}")

    print(f"🚦 Quality Gate  : " f"{quality_gate}")

    print(f"🔍 Issues        : " f"{total_issues}")

    print()

    if total_issues == 0:

        print("✅ No security issues found.")

    else:

        print("Findings:")

        print()

        for finding in result.get(
            "findings",
            [],
        ):

            filename = finding.get(
                "filename",
                "Unknown",
            )

            line = finding.get(
                "line",
                "Unknown",
            )

            error = finding.get(
                "error",
                "Unknown issue",
            )

            severity = finding.get(
                "severity",
                "Unknown",
            )

            print(f"  📄 {filename} " f"(line {line})")

            print(f"  ❌ {error}")

            print(f"  ⚠️ Severity: " f"{severity}")

            print()

    print("=" * 75)


# =========================================================
# CLEAN TEMPORARY DIRECTORY
# =========================================================


def cleanup_temp_directory(
    temp_dir,
    max_attempts=5,
):
    """
    Remove the temporary cloned repository.

    Windows may temporarily keep Git/SonarScanner
    files locked. Therefore, deletion is retried.

    The function also handles read-only files.
    """

    if not temp_dir:

        return

    if not os.path.exists(temp_dir):

        return

    print()

    print("Cleaning up temporary files...")

    # -----------------------------------------------------
    # Function used when shutil.rmtree encounters a
    # read-only file.
    # -----------------------------------------------------

    def handle_remove_error(
        func,
        path,
        exc_info,
    ):

        try:

            os.chmod(
                path,
                0o777,
            )

        except Exception:

            pass

        try:

            func(path)

        except Exception:

            pass

    # -----------------------------------------------------
    # Retry several times because Windows can temporarily
    # keep a Git/SonarScanner file open.
    # -----------------------------------------------------

    for attempt in range(
        1,
        max_attempts + 1,
    ):

        try:

            shutil.rmtree(
                temp_dir,
                onerror=handle_remove_error,
            )

            if not os.path.exists(temp_dir):

                print("Temporary repository " "removed successfully.")

                return

        except Exception as e:

            if attempt == max_attempts:

                print(
                    "Warning: Temporary directory " "could not be completely removed."
                )

                print(f"Details: {str(e)}")

                return

        # -------------------------------------------------
        # Give Windows time to release file handles.
        # -------------------------------------------------

        time.sleep(2)


# =========================================================
# MAIN SONARCLOUD SCAN
# =========================================================


def run_sonarqube_scan(
    pr_url,
    include_details=True,
):
    """
    Complete SonarCloud PR security scan.

    Flow:

    GitHub PR
        ↓
    Clone repository
        ↓
    Checkout exact PR commit
        ↓
    Run SonarScanner
        ↓
    Wait for analysis
        ↓
    Quality Gate
        ↓
    Issues
        ↓
    Dynamic Rule Details
        ↓
    Final Result
        ↓
    Delete Temporary Clone
    """

    temp_dir = None

    try:

        # =================================================
        # CHECK CONFIGURATION
        # =================================================

        if not SONAR_ORGANIZATION:

            print("Error: SONAR_ORGANIZATION " "is missing from .env.")

            return None

        if not SONAR_PROJECT_KEY:

            print("Error: SONAR_PROJECT_KEY " "is missing from .env.")

            return None

        if not SONAR_TOKEN:

            print("Error: SONAR_TOKEN " "is missing from .env.")

            return None

        scanner = find_sonar_scanner()

        if not scanner:

            print("Error: SonarScanner was not found.")

            print("Set SONAR_SCANNER_PATH in .env " "or add SonarScanner to PATH.")

            return None

        # =================================================
        # GET GITHUB PR DETAILS
        # =================================================

        pr_details = github_client.fetch_pr_details(pr_url)

        if not pr_details:

            print("Error: Could not fetch " "Pull Request details.")

            return None

        owner = pr_details["owner"]

        repo = pr_details["repo"]

        pull_number = pr_details["pull_number"]

        head_branch = pr_details["head_branch"]

        base_branch = pr_details["base_branch"]

        head_sha = pr_details["head_sha"]

        clone_url = pr_details["clone_url"]

        print()

        print(f"PR number: " f"{pull_number}")

        print(f"PR source branch: " f"{head_branch}")

        print(f"PR target branch: " f"{base_branch}")

        # =================================================
        # CREATE TEMPORARY DIRECTORY
        # =================================================

        temp_dir = tempfile.mkdtemp(prefix="release_portal_sonar_")

        repo_dir = os.path.join(
            temp_dir,
            "repository",
        )

        print()

        print("Cloning repository...")

        # =================================================
        # CLONE REPOSITORY
        # =================================================

        clone_result = subprocess.run(
            [
                "git",
                "clone",
                clone_url,
                repo_dir,
            ],
            capture_output=True,
            text=True,
        )

        if clone_result.returncode != 0:

            print(
                "❌ Error cloning repository:",
                file=sys.stderr,
            )

            print(
                clone_result.stderr,
                file=sys.stderr,
            )

            return None

        # =================================================
        # CHECKOUT EXACT PR COMMIT
        # =================================================

        print()

        print(f"Checking out PR commit: " f"{head_sha}")

        checkout_result = subprocess.run(
            [
                "git",
                "-C",
                repo_dir,
                "checkout",
                head_sha,
            ],
            capture_output=True,
            text=True,
        )

        if checkout_result.returncode != 0:

            print(
                "❌ Error checking out " "PR commit:",
                file=sys.stderr,
            )

            print(
                checkout_result.stderr,
                file=sys.stderr,
            )

            return None

        # =================================================
        # RUN SONARSCANNER
        # =================================================

        print()

        print("Running SonarCloud scan...")

        scanner_command = [
            scanner,
            f"-Dsonar.host.url=" f"{SONAR_HOST}",
            f"-Dsonar.token=" f"{SONAR_TOKEN}",
            f"-Dsonar.organization=" f"{SONAR_ORGANIZATION}",
            f"-Dsonar.projectKey=" f"{SONAR_PROJECT_KEY}",
            f"-Dsonar.projectName=" f"{repo}",
            # Dynamic PR number
            f"-Dsonar.pullrequest.key=" f"{pull_number}",
            # Dynamic source branch
            f"-Dsonar.pullrequest.branch=" f"{head_branch}",
            # Dynamic target branch
            f"-Dsonar.pullrequest.base=" f"{base_branch}",
        ]

        scan_result = subprocess.run(
            scanner_command,
            cwd=repo_dir,
            capture_output=True,
            text=True,
        )

        if scan_result.returncode != 0:

            print()

            print(
                "❌ SonarCloud scan failed.",
                file=sys.stderr,
            )

            print()

            print(scan_result.stdout)

            print(
                scan_result.stderr,
                file=sys.stderr,
            )

            return None

        print("SonarCloud scan completed.")

        # =================================================
        # FIND CE TASK ID
        # =================================================

        task_id = None

        report_task_file = os.path.join(
            repo_dir,
            ".scannerwork",
            "report-task.txt",
        )

        # -------------------------------------------------
        # Primary method:
        # .scannerwork/report-task.txt
        # -------------------------------------------------

        if os.path.exists(report_task_file):

            with open(
                report_task_file,
                "r",
                encoding="utf-8",
            ) as file:

                for line in file:

                    line = line.strip()

                    if line.startswith("ceTaskId="):

                        task_id = line.split(
                            "=",
                            1,
                        )[1].strip()

                        break

        # =================================================
        # FALLBACK 1: SCANNER OUTPUT
        # =================================================

        if not task_id:

            match = re.search(
                r"ceTaskId[=:]\s*" r"([A-Za-z0-9_-]+)",
                scan_result.stdout,
            )

            if match:

                task_id = match.group(1)

        # =================================================
        # FALLBACK 2: TASK URL
        # =================================================

        if not task_id:

            match = re.search(
                r"task\?id=" r"([A-Za-z0-9_-]+)",
                scan_result.stdout,
            )

            if match:

                task_id = match.group(1)

        # =================================================
        # MAKE SURE TASK ID EXISTS
        # =================================================

        if not task_id:

            print()

            print("❌ Could not find " "SonarCloud analysis task ID.")

            print()

            print("SonarScanner output:")

            print(scan_result.stdout)

            return None

        # =================================================
        # WAIT FOR ANALYSIS
        # =================================================

        analysis = wait_for_analysis(task_id)

        if not analysis:

            return None

        # =================================================
        # FETCH QUALITY GATE
        # =================================================

        print()

        print("Fetching SonarCloud " "Quality Gate...")

        quality_gate_data = sonar_request(
            "/api/qualitygates/project_status",
            params={
                "projectKey": SONAR_PROJECT_KEY,
                "pullRequest": pull_number,
            },
        )

        if not quality_gate_data:

            print("Error: Could not retrieve " "SonarCloud Quality Gate.")

            return None

        project_status = quality_gate_data.get(
            "projectStatus",
            {},
        )

        quality_gate = project_status.get(
            "status",
            "UNKNOWN",
        )

        # =================================================
        # FETCH SONARCLOUD ISSUES
        # =================================================

        print("Fetching SonarCloud issues...")

        issues_data = sonar_request(
            "/api/issues/search",
            params={
                "componentKeys": SONAR_PROJECT_KEY,
                "pullRequest": pull_number,
                "resolved": "false",
                "ps": 500,
            },
        )

        if not issues_data:

            print("Error: Could not retrieve " "SonarCloud issues.")

            return None

        issues = issues_data.get(
            "issues",
            [],
        )

        # =================================================
        # BUILD FINDINGS
        # =================================================

        findings = []

        for issue in issues:

            # -------------------------------------------------
            # Dynamic rule ID
            # -------------------------------------------------

            rule_key = issue.get(
                "rule",
                "Unknown",
            )

            # -------------------------------------------------
            # Get dynamic rule details
            # -------------------------------------------------

            rule_details = get_rule_details(rule_key)

            # -------------------------------------------------
            # Extract filename
            # -------------------------------------------------

            component = issue.get(
                "component",
                "",
            )

            filename = component

            if ":" in component:

                filename = component.split(
                    ":",
                    1,
                )[-1]

            # -------------------------------------------------
            # Build finding
            # -------------------------------------------------

            finding = {
                "filename": filename,
                "line": issue.get("line"),
                "error": issue.get(
                    "message",
                    "No issue description " "available.",
                ),
                "severity": issue.get(
                    "severity",
                    "UNKNOWN",
                ),
                "type": issue.get(
                    "type",
                    "UNKNOWN",
                ),
                "rule_name": rule_details["rule_name"],
            }

            # -------------------------------------------------
            # Detailed information is included only when
            # the user selected "y".
            # -------------------------------------------------

            if include_details:

                finding["reason"] = rule_details["reason"]

                finding["recommendation"] = rule_details["recommendation"]

            findings.append(finding)

        # =================================================
        # BUILD FINAL RESULT
        # =================================================

        result = {
            "tool": "SonarCloud",
            "status": "SUCCESS",
            "quality_gate": quality_gate,
            "total_issues": len(findings),
            "findings": findings,
        }

        # =================================================
        # DISPLAY HUMAN-READABLE RESULT
        # =================================================

        if include_details:

            display_detailed_findings(findings)

        else:

            display_summary(result)

        # =================================================
        # PRINT FINAL JSON
        # =================================================

        print()

        print("=" * 70)

        print("📦 FINAL JSON RESULT")

        print("=" * 70)

        print(
            json.dumps(
                result,
                indent=2,
            )
        )

        print("=" * 70)

        return result

    # =====================================================
    # HANDLE CTRL+C
    # =====================================================

    except KeyboardInterrupt:

        print()

        print("Scan interrupted by user.")

        return None

    # =====================================================
    # HANDLE UNEXPECTED ERRORS
    # =====================================================

    except Exception as e:

        print()

        print(
            f"Unexpected error: " f"{str(e)}",
            file=sys.stderr,
        )

        return None

    # =====================================================
    # ALWAYS CLEAN TEMPORARY REPOSITORY
    # =====================================================

    finally:

        cleanup_temp_directory(temp_dir)

"""
# =========================================================
# COMMAND-LINE ENTRY POINT
# =========================================================


if __name__ == "__main__":

    if len(sys.argv) != 2:

        print()

        print("Usage:")

        print("python -m src.checks.sonarqube " '"<GitHub Pull Request URL>"')

        print()

        print("Or:")

        print("python .\\src\\checks\\sonarqube.py " '"<GitHub Pull Request URL>"')

        sys.exit(1)

    pr_url = sys.argv[1]

    # =====================================================
    # ASK USER WHETHER DETAILED INFORMATION IS REQUIRED
    # =====================================================

    while True:

        choice = (
            input(
                "Do you have time to review detailed "
                "SonarCloud reasons and recommendations? "
                "(y/n): "
            )
            .strip()
            .lower()
        )

        if choice in (
            "y",
            "n",
        ):

            break

        print("Please enter either y or n.")

    include_details = choice == "y"

    # =====================================================
    # RUN SCAN
    # =====================================================

    run_sonarqube_scan(
        pr_url,
        include_details=include_details,
    )
"""