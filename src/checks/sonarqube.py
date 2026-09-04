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

# ---------------------------------------------------------
# Allow importing github_client.py from src/
# ---------------------------------------------------------

sys.path.insert(
    0,
    os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
        )
    ),
)

from github_client import fetch_pr_details

load_dotenv()


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

SONAR_TOKEN_ERROR = "SONAR_TOKEN is not configured."

SONAR_SCANNER = (
    r"C:\Users\Himani Dhawan\Downloads"
    r"\sonar-scanner-cli-8.1.0.6389-windows-x64"
    r"\sonar-scanner-8.1.0.6389-windows-x64"
    r"\bin\sonar-scanner.bat"
)


# ---------------------------------------------------------
# Utility functions
# ---------------------------------------------------------


def clean_html(text):
    """Remove HTML tags and extra whitespace."""

    if not text:
        return None

    # Convert common HTML elements into readable spacing
    text = re.sub(
        r"<br\s*/?>",
        "\n",
        text,
        flags=re.IGNORECASE,
    )

    text = re.sub(
        r"</p\s*>",
        "\n",
        text,
        flags=re.IGNORECASE,
    )

    text = re.sub(
        r"</li\s*>",
        "\n",
        text,
        flags=re.IGNORECASE,
    )

    # Remove remaining HTML tags
    text = re.sub(
        r"<[^>]+>",
        " ",
        text,
    )

    # Decode common HTML entities
    text = (
        text.replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", '"')
        .replace("&#39;", "'")
    )

    # Clean spaces
    text = re.sub(
        r"[ \t]+",
        " ",
        text,
    )

    # Clean excessive blank lines
    text = re.sub(
        r"\n\s*\n+",
        "\n\n",
        text,
    )

    return text.strip()


def get_project_root():
    """Return the project root directory."""

    return os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            "..",
            "..",
        )
    )


# ---------------------------------------------------------
# Copy SonarCloud configuration
# ---------------------------------------------------------


def copy_sonar_properties(workspace):
    """Copy sonar-project.properties to temporary workspace."""

    project_root = get_project_root()

    source = os.path.join(
        project_root,
        "sonar-project.properties",
    )

    destination = os.path.join(
        workspace,
        "sonar-project.properties",
    )

    if not os.path.exists(source):
        return {
            "status": "ERROR",
            "message": "sonar-project.properties not found.",
        }

    try:

        shutil.copy2(
            source,
            destination,
        )

        return {
            "status": "SUCCESS",
        }

    except Exception as exc:

        return {
            "status": "ERROR",
            "message": "Unable to copy sonar-project.properties.",
            "details": str(exc),
        }


# ---------------------------------------------------------
# Prepare PR workspace
# ---------------------------------------------------------


def prepare_pr_workspace(pr_details):
    """
    Clone the repository and checkout the exact PR commit.
    """

    required_fields = [
        "clone_url",
        "head_sha",
        "owner",
        "repo",
        "pull_number",
    ]

    for field in required_fields:

        if not pr_details.get(field):

            return (
                None,
                f"Missing PR detail: {field}",
            )

    workspace = tempfile.mkdtemp(prefix="release_gate_sonar_")

    try:

        # -------------------------------------------------
        # Clone repository
        # -------------------------------------------------

        clone_result = subprocess.run(
            [
                "git",
                "clone",
                pr_details["clone_url"],
                workspace,
            ],
            capture_output=True,
            text=True,
        )

        if clone_result.returncode != 0:

            return (
                None,
                f"Git clone failed:\n{clone_result.stderr}",
            )

        # -------------------------------------------------
        # Fetch exact PR commit
        # -------------------------------------------------

        fetch_result = subprocess.run(
            [
                "git",
                "fetch",
                "origin",
                pr_details["head_sha"],
            ],
            cwd=workspace,
            capture_output=True,
            text=True,
        )

        if fetch_result.returncode != 0:

            return (
                None,
                f"Git fetch failed:\n{fetch_result.stderr}",
            )

        # -------------------------------------------------
        # Checkout exact commit
        # -------------------------------------------------

        checkout_result = subprocess.run(
            [
                "git",
                "checkout",
                "--detach",
                pr_details["head_sha"],
            ],
            cwd=workspace,
            capture_output=True,
            text=True,
        )

        if checkout_result.returncode != 0:

            return (
                None,
                f"Git checkout failed:\n{checkout_result.stderr}",
            )

        # -------------------------------------------------
        # Copy Sonar configuration
        # -------------------------------------------------

        config_result = copy_sonar_properties(workspace)

        if config_result["status"] != "SUCCESS":

            return (
                None,
                config_result["message"],
            )

        return (
            workspace,
            None,
        )

    except Exception as exc:

        return (
            None,
            str(exc),
        )


# ---------------------------------------------------------
# Run SonarScanner
# ---------------------------------------------------------


def run_sonar_scan(workspace):
    """Run SonarScanner."""

    sonar_token = os.getenv("SONAR_TOKEN")

    if not sonar_token:

        return {
            "status": "ERROR",
            "message": SONAR_TOKEN_ERROR,
        }

    if not os.path.exists(SONAR_SCANNER):

        return {
            "status": "ERROR",
            "message": "SonarScanner executable not found.",
            "details": SONAR_SCANNER,
        }

    try:

        result = subprocess.run(
            [
                SONAR_SCANNER,
                f"-Dsonar.token={sonar_token}",
            ],
            cwd=workspace,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:

            return {
                "status": "ERROR",
                "message": "SonarScanner execution failed.",
                "details": (result.stdout + "\n" + result.stderr),
            }

        return {
            "status": "SUCCESS",
        }

    except Exception as exc:

        return {
            "status": "ERROR",
            "message": "Unable to run SonarScanner.",
            "details": str(exc),
        }


# ---------------------------------------------------------
# Read SonarScanner task details
# ---------------------------------------------------------


def get_sonar_task_details(workspace):
    """Read SonarScanner report-task.txt."""

    report_file = os.path.join(
        workspace,
        ".scannerwork",
        "report-task.txt",
    )

    if not os.path.exists(report_file):

        return {
            "status": "ERROR",
            "message": "SonarScanner report-task.txt not found.",
        }

    properties = {}

    try:

        with open(
            report_file,
            "r",
            encoding="utf-8",
        ) as file:

            for line in file:

                line = line.strip()

                if "=" in line:

                    key, value = line.split(
                        "=",
                        1,
                    )

                    properties[key] = value

        ce_task_id = properties.get("ceTaskId")

        project_key = properties.get("projectKey")

        if not ce_task_id:

            return {
                "status": "ERROR",
                "message": "SonarCloud CE task ID was not found.",
            }

        if not project_key:

            return {
                "status": "ERROR",
                "message": "SonarCloud project key was not found.",
            }

        return {
            "status": "SUCCESS",
            "ce_task_id": ce_task_id,
            "project_key": project_key,
        }

    except Exception as exc:

        return {
            "status": "ERROR",
            "message": "Unable to read Sonar task details.",
            "details": str(exc),
        }


# ---------------------------------------------------------
# Wait for SonarCloud analysis
# ---------------------------------------------------------


def wait_for_sonar_analysis(ce_task_id):
    """Wait for SonarCloud analysis to finish."""

    sonar_token = os.getenv("SONAR_TOKEN")

    if not sonar_token:

        return {
            "status": "ERROR",
            "message": SONAR_TOKEN_ERROR,
        }

    url = "https://sonarcloud.io/api/ce/task"

    for _ in range(60):

        try:

            response = requests.get(
                url,
                params={
                    "id": ce_task_id,
                },
                auth=(
                    sonar_token,
                    "",
                ),
                timeout=20,
            )

            if response.status_code != 200:

                return {
                    "status": "ERROR",
                    "message": ("Unable to check " "SonarCloud analysis status."),
                    "details": response.text,
                }

            data = response.json()

            task = data.get(
                "task",
                {},
            )

            status = task.get("status")

            if status == "SUCCESS":

                return {
                    "status": "SUCCESS",
                    "analysis_id": task.get("analysisId"),
                }

            if status in {
                "FAILED",
                "CANCELED",
            }:

                return {
                    "status": "ERROR",
                    "message": ("SonarCloud analysis " f"{status.lower()}."),
                }

            time.sleep(2)

        except Exception as exc:

            return {
                "status": "ERROR",
                "message": ("Error while waiting " "for SonarCloud."),
                "details": str(exc),
            }

    return {
        "status": "ERROR",
        "message": "SonarCloud analysis timed out.",
    }


# ---------------------------------------------------------
# Quality Gate
# ---------------------------------------------------------


def get_quality_gate(analysis_id):
    """Get SonarCloud Quality Gate result."""

    sonar_token = os.getenv("SONAR_TOKEN")

    if not sonar_token:

        return {
            "status": "ERROR",
            "message": SONAR_TOKEN_ERROR,
        }

    url = "https://sonarcloud.io/api/qualitygates/" "project_status"

    try:

        response = requests.get(
            url,
            params={
                "analysisId": analysis_id,
            },
            auth=(
                sonar_token,
                "",
            ),
            timeout=20,
        )

        if response.status_code != 200:

            return {
                "status": "ERROR",
                "message": "Unable to fetch Quality Gate.",
                "details": response.text,
            }

        data = response.json()

        project_status = data.get(
            "projectStatus",
            {},
        )

        return {
            "status": "SUCCESS",
            "quality_gate": project_status.get(
                "status",
                "UNKNOWN",
            ),
            "conditions": project_status.get(
                "conditions",
                [],
            ),
        }

    except Exception as exc:

        return {
            "status": "ERROR",
            "message": "Unable to process Quality Gate.",
            "details": str(exc),
        }


# ---------------------------------------------------------
# Extract recommendation from rule description
# ---------------------------------------------------------


def extract_recommendation(description):
    """
    Try to extract remediation/fix guidance from the
    SonarCloud rule description.

    This works with different rule descriptions and does
    not depend on a specific rule key.
    """

    if not description:

        return None

    lines = [line.strip() for line in description.splitlines() if line.strip()]

    if not lines:

        return None

    # Look for common remediation headings
    recommendation_keywords = [
        "how to fix",
        "how to fix it",
        "fix",
        "fixing",
        "remediation",
        "recommended",
        "recommendation",
        "compliant solution",
        "noncompliant code",
        "compliant code",
        "correct solution",
        "solution",
    ]

    for index, line in enumerate(lines):

        lower_line = line.lower()

        for keyword in recommendation_keywords:

            if keyword in lower_line:

                # Try the text after the heading
                remainder = re.sub(
                    rf"^.*?{re.escape(keyword)}\s*:?\s*",
                    "",
                    line,
                    flags=re.IGNORECASE,
                ).strip()

                if remainder and len(remainder) > 15:

                    return remainder

                # Otherwise use the next useful line
                for next_line in lines[index + 1 :]:

                    if len(next_line) > 20:

                        return next_line

    return None


# ---------------------------------------------------------
# Generate generic recommendation
# ---------------------------------------------------------


def generate_generic_recommendation(
    issue,
    rule_details,
):
    """
    Generate a recommendation when SonarCloud does not
    provide explicit remediation text.
    """

    rule_name = rule_details.get("name")

    if rule_name:

        return (
            f"Review the code related to the "
            f"'{rule_name}' rule and modify it "
            f"to comply with the SonarCloud recommendation."
        )

    rule_key = issue.get(
        "rule",
        "this rule",
    )

    return (
        f"Review the affected code and remediate "
        f"the issue according to SonarCloud rule "
        f"{rule_key}."
    )


# ---------------------------------------------------------
# Get SonarCloud rule details
# ---------------------------------------------------------


def get_sonar_rule_details(
    rule_key,
    issue=None,
):
    """
    Get rule information dynamically from SonarCloud.

    No individual SonarCloud rule is hard-coded here.
    """

    if issue is None:
        issue = {}

    sonar_token = os.getenv("SONAR_TOKEN")

    if not sonar_token:

        return {
            "reason": ("SonarCloud identified a security " "or code-quality issue."),
            "recommendation": (
                "Review and remediate the issue " "according to the SonarCloud rule."
            ),
        }

    url = "https://sonarcloud.io/api/rules/show"

    try:

        response = requests.get(
            url,
            params={
                "key": rule_key,
                "actives": "true",
            },
            auth=(
                sonar_token,
                "",
            ),
            timeout=20,
        )

        if response.status_code != 200:

            return {
                "reason": ("SonarCloud identified an issue " "for this rule."),
                "recommendation": (
                    "Review the affected code and "
                    "remediate it according to "
                    f"SonarCloud rule {rule_key}."
                ),
            }

        data = response.json()

        rule = data.get(
            "rule",
            {},
        )

        # -------------------------------------------------
        # Rule name
        # -------------------------------------------------

        rule_name = rule.get("name")

        # -------------------------------------------------
        # Try all commonly available description fields
        # -------------------------------------------------

        description = None

        description_fields = [
            "htmlDesc",
            "mdDesc",
            "description",
            "markdownDescription",
        ]

        for field in description_fields:

            value = rule.get(field)

            if (
                isinstance(
                    value,
                    str,
                )
                and value.strip()
            ):

                if field.startswith("html"):

                    description = clean_html(value)

                else:

                    description = value.strip()

                if description:

                    break

        # -------------------------------------------------
        # Extended/custom rule description
        # -------------------------------------------------

        if not description:

            extended_fields = [
                "htmlNote",
                "mdNote",
            ]

            for field in extended_fields:

                value = rule.get(field)

                if (
                    isinstance(
                        value,
                        str,
                    )
                    and value.strip()
                ):

                    if field.startswith("html"):

                        description = clean_html(value)

                    else:

                        description = value.strip()

                    if description:

                        break

        # -------------------------------------------------
        # Reason
        # -------------------------------------------------

        if description:

            reason = description

        else:

            reason = "SonarCloud identified an issue " "related to this rule."

        # -------------------------------------------------
        # Recommendation
        # -------------------------------------------------

        recommendation = extract_recommendation(description) if description else None

        if not recommendation:

            recommendation = generate_generic_recommendation(
                issue,
                {
                    "name": rule_name,
                },
            )

        return {
            "reason": reason,
            "recommendation": recommendation,
            "name": rule_name,
        }

    except Exception:

        return {
            "reason": ("SonarCloud identified an issue " "related to this rule."),
            "recommendation": (
                "Review the affected code and "
                "remediate it according to "
                f"SonarCloud rule {rule_key}."
            ),
        }


# ---------------------------------------------------------
# Create finding
# ---------------------------------------------------------


def create_sonar_finding(
    issue,
    include_details=False,
):
    """
    N:
        file + line + message + reason

    Y:
        file + line + message + reason + recommendation
    """

    component = issue.get(
        "component",
        "",
    )

    # -----------------------------------------------------
    # Remove project key from filename
    #
    # Example:
    #
    # my-project:iam.tf
    #
    # becomes:
    #
    # iam.tf
    # -----------------------------------------------------

    filename = component

    if ":" in filename:

        filename = filename.split(
            ":",
            1,
        )[1]

    rule_key = issue.get(
        "rule",
        "Unknown",
    )

    # -----------------------------------------------------
    # Basic finding
    # -----------------------------------------------------

    finding = {
        "engine": "SonarCloud",
        "rule": rule_key,
        "severity": issue.get(
            "severity",
            "UNKNOWN",
        ),
        "type": issue.get(
            "type",
            "UNKNOWN",
        ),
        "message": issue.get(
            "message",
            "",
        ),
        "file": filename,
        "line": issue.get("line"),
    }

    # -----------------------------------------------------
    # Get dynamic rule details
    # -----------------------------------------------------

    details = get_sonar_rule_details(
        rule_key,
        issue,
    )

    # -----------------------------------------------------
    # Reason is ALWAYS shown
    # -----------------------------------------------------

    finding["reason"] = details.get(
        "reason",
        "SonarCloud identified an issue that should be reviewed.",
    )

    # -----------------------------------------------------
    # Recommendation only for Y
    # -----------------------------------------------------

    if include_details:

        finding["recommendation"] = details.get(
            "recommendation",
            "Review and remediate the issue according to the SonarCloud rule.",
        )

    return finding


# ---------------------------------------------------------
# Get SonarCloud issues
# ---------------------------------------------------------


def get_sonar_issues(
    project_key,
    include_details=False,
):
    """Get unresolved SonarCloud issues."""

    sonar_token = os.getenv("SONAR_TOKEN")

    if not sonar_token:

        return {
            "status": "ERROR",
            "message": SONAR_TOKEN_ERROR,
        }

    url = "https://sonarcloud.io/api/issues/search"

    params = {
        "componentKeys": project_key,
        "resolved": "false",
        "ps": 500,
    }

    try:

        response = requests.get(
            url,
            params=params,
            auth=(
                sonar_token,
                "",
            ),
            timeout=20,
        )

        if response.status_code != 200:

            return {
                "status": "ERROR",
                "message": "Unable to fetch SonarCloud issues.",
                "details": response.text,
            }

        data = response.json()

        issues = data.get(
            "issues",
            [],
        )

        findings = []

        for issue in issues:

            findings.append(
                create_sonar_finding(
                    issue,
                    include_details,
                )
            )

        return {
            "status": "SUCCESS",
            "total": len(findings),
            "findings": findings,
        }

    except Exception as exc:

        return {
            "status": "ERROR",
            "message": "Unable to process SonarCloud issues.",
            "details": str(exc),
        }


# ---------------------------------------------------------
# Main SonarCloud security check
# ---------------------------------------------------------


def run_sonar_security_check(
    pr_details,
    include_details=False,
):
    """Run complete SonarCloud security check."""

    workspace = None

    try:

        # -------------------------------------------------
        # Prepare workspace
        # -------------------------------------------------

        workspace, workspace_error = prepare_pr_workspace(pr_details)

        if not workspace:

            return {
                "status": "ERROR",
                "message": ("Unable to prepare " "PR workspace."),
                "details": workspace_error,
            }

        # -------------------------------------------------
        # Run SonarScanner
        # -------------------------------------------------

        scan_result = run_sonar_scan(workspace)

        if scan_result["status"] != "SUCCESS":

            return scan_result

        # -------------------------------------------------
        # Read task details
        # -------------------------------------------------

        task_details = get_sonar_task_details(workspace)

        if task_details["status"] != "SUCCESS":

            return task_details

        project_key = task_details["project_key"]

        ce_task_id = task_details["ce_task_id"]

        # -------------------------------------------------
        # Wait for analysis
        # -------------------------------------------------

        analysis_result = wait_for_sonar_analysis(ce_task_id)

        if analysis_result["status"] != "SUCCESS":

            return analysis_result

        analysis_id = analysis_result["analysis_id"]

        # -------------------------------------------------
        # Get Quality Gate
        # -------------------------------------------------

        quality_gate = get_quality_gate(analysis_id)

        if quality_gate["status"] != "SUCCESS":

            return quality_gate

        # -------------------------------------------------
        # Get issues
        # -------------------------------------------------

        issues = get_sonar_issues(
            project_key,
            include_details,
        )

        if issues["status"] != "SUCCESS":

            return issues

        # -------------------------------------------------
        # Final result
        # -------------------------------------------------

        return {
            "status": "SUCCESS",
            "repository": (f"{pr_details['owner']}/" f"{pr_details['repo']}"),
            "pull_request": (pr_details["pull_number"]),
            "head_sha": (pr_details["head_sha"]),
            "project_key": project_key,
            "analysis_id": analysis_id,
            "quality_gate": (quality_gate["quality_gate"]),
            "total_issues": (issues["total"]),
            "findings": issues["findings"],
        }

    finally:

        # -------------------------------------------------
        # Delete temporary workspace
        # -------------------------------------------------

        if workspace and os.path.exists(workspace):

            shutil.rmtree(
                workspace,
                ignore_errors=True,
            )


# ---------------------------------------------------------
# Program entry point
# ---------------------------------------------------------

if __name__ == "__main__":

    # -----------------------------------------------------
    # Check PR URL
    # -----------------------------------------------------

    if len(sys.argv) != 2:

        print("Usage: python sonarqube.py " "<GitHub_PR_URL>")

        sys.exit(1)

    pr_url = sys.argv[1]

    # -----------------------------------------------------
    # Ask user about details
    # -----------------------------------------------------

    print()

    print(
        "Do you have time to review detailed " "SonarCloud reasons and recommendations?"
    )

    print("Enter 'y' for detailed findings or " "'n' for the main findings only.")

    # -----------------------------------------------------
    # Validate input
    # -----------------------------------------------------

    while True:

        choice = input("Your choice (y/n): ").strip().lower()

        if choice in {
            "y",
            "n",
        }:

            break

        print("Invalid choice. Please enter y or n.")

        print()

    # -----------------------------------------------------
    # Decide whether recommendations are included
    # -----------------------------------------------------

    include_details = choice == "y"

    print()

    # -----------------------------------------------------
    # Fetch PR details
    # -----------------------------------------------------

    print("Fetching Pull Request details...")

    pr_details = fetch_pr_details(pr_url)

    if not pr_details:

        print(
            json.dumps(
                {
                    "status": "ERROR",
                    "message": ("Unable to fetch " "Pull Request details."),
                },
                indent=2,
            )
        )

        sys.exit(1)

    # -----------------------------------------------------
    # Run security check
    # -----------------------------------------------------

    print("Running SonarCloud security check...")

    print()

    result = run_sonar_security_check(
        pr_details,
        include_details=include_details,
    )

    # -----------------------------------------------------
    # Print JSON result
    # -----------------------------------------------------

    print(
        json.dumps(
            result,
            indent=2,
        )
    )
