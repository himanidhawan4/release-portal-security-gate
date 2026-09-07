import sys
import requests
from dotenv import load_dotenv
import os

load_dotenv()


def fetch_pr_details(pr_url):
    """
    Fetch complete GitHub Pull Request information.

    The function dynamically extracts:
    - owner
    - repository
    - PR number
    - source/head branch
    - target/base branch
    - head commit SHA
    - clone URL
    - changed files and patches

    Nothing is hard-coded for a particular repository or PR.
    """

    parts = pr_url.rstrip("/").split("/")

    if "pull" not in parts:
        print(
            "Error: Invalid GitHub Pull Request URL. " "Missing '/pull/'.",
            file=sys.stderr,
        )
        return None

    try:
        pull_index = parts.index("pull")

        pull_number = parts[pull_index + 1]

        # GitHub URL format:
        # https://github.com/OWNER/REPOSITORY/pull/NUMBER
        owner = parts[3]
        repo = parts[4]

    except (ValueError, IndexError):
        print(
            "Error: Invalid GitHub Pull Request URL.",
            file=sys.stderr,
        )
        return None

    github_token = os.getenv("GITHUB_TOKEN")

    if not github_token:
        print(
            "Error: GITHUB_TOKEN is not configured in .env",
            file=sys.stderr,
        )
        return None

    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
    }

    # ---------------------------------------------------------
    # Fetch Pull Request details
    # ---------------------------------------------------------

    pr_api_url = f"https://api.github.com/repos/" f"{owner}/{repo}/pulls/{pull_number}"

    try:
        response = requests.get(
            pr_api_url,
            headers=headers,
            timeout=30,
        )
    except requests.RequestException as e:
        print(
            f"Error connecting to GitHub: {str(e)}",
            file=sys.stderr,
        )
        return None

    if response.status_code == 401:
        print(
            "Error 401: GitHub token is invalid, " "expired, or revoked.",
            file=sys.stderr,
        )
        return None

    if response.status_code == 403:
        print(
            "Error 403: GitHub token is valid, "
            "but does not have sufficient permission.",
            file=sys.stderr,
        )
        return None

    if response.status_code == 404:
        print(
            "Error 404: Pull Request or repository not found.",
            file=sys.stderr,
        )
        return None

    if response.status_code != 200:
        print(
            "Error fetching Pull Request:",
            response.status_code,
            response.text,
            file=sys.stderr,
        )
        return None

    pr_data = response.json()

    # ---------------------------------------------------------
    # Dynamically extract branch and commit information
    # ---------------------------------------------------------

    head_data = pr_data.get("head", {})
    base_data = pr_data.get("base", {})

    head_branch = head_data.get("ref")
    base_branch = base_data.get("ref")
    head_sha = head_data.get("sha")

    if not head_branch:
        print(
            "Error: Could not determine PR source/head branch.",
            file=sys.stderr,
        )
        return None

    if not base_branch:
        print(
            "Error: Could not determine PR target/base branch.",
            file=sys.stderr,
        )
        return None

    if not head_sha:
        print(
            "Error: Could not determine PR head SHA.",
            file=sys.stderr,
        )
        return None

    # Use the repository associated with the PR head.
    head_repo = head_data.get("repo") or {}
    clone_url = head_repo.get("clone_url")

    if not clone_url:
        # Fallback to the main repository clone URL.
        clone_url = pr_data.get("base", {}).get("repo", {}).get("clone_url")

    if not clone_url:
        print(
            "Error: Could not determine repository clone URL.",
            file=sys.stderr,
        )
        return None

    # ---------------------------------------------------------
    # Fetch changed files
    # ---------------------------------------------------------

    files_api_url = (
        f"https://api.github.com/repos/" f"{owner}/{repo}/pulls/{pull_number}/files"
    )

    try:
        files_response = requests.get(
            files_api_url,
            headers=headers,
            timeout=30,
        )
    except requests.RequestException as e:
        print(
            f"Error fetching changed files: {str(e)}",
            file=sys.stderr,
        )
        return None

    if files_response.status_code != 200:
        print(
            "Error fetching PR files:",
            files_response.status_code,
            files_response.text,
            file=sys.stderr,
        )
        return None

    changed_files = []

    for item in files_response.json():
        filename = item.get("filename") or "No filename available"
        patch = item.get("patch") or ""

        changed_files.append(
            (
                filename,
                patch,
            )
        )

    # ---------------------------------------------------------
    # Return all required PR information
    # ---------------------------------------------------------

    return {
        "owner": owner,
        "repo": repo,
        "pull_number": pull_number,
        # SonarCloud PR analysis information
        "head_branch": head_branch,
        "base_branch": base_branch,
        "head_sha": head_sha,
        # Repository information
        "clone_url": clone_url,
        # GitHub PR changes
        "changed_files": changed_files,
    }


# -------------------------------------------------------------
# Standalone testing
# -------------------------------------------------------------
"""
if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python github_client.py " "<GitHub Pull Request URL>")
        sys.exit(1)

    pr_url = sys.argv[1]

    pr_details = fetch_pr_details(pr_url)

    if not pr_details:
        sys.exit(1)

    print("\nPR Details:\n")

    print(f"Repository: " f"{pr_details['owner']}/{pr_details['repo']}")

    print(f"Pull Request: " f"{pr_details['pull_number']}")

    print(f"Source Branch: " f"{pr_details['head_branch']}")

    print(f"Target Branch: " f"{pr_details['base_branch']}")

    print(f"Head SHA: " f"{pr_details['head_sha']}")

    print(f"Clone URL: " f"{pr_details['clone_url']}")

    print("\nChanged Files:\n")

    for filename, patch in pr_details["changed_files"]:

        print(f"Filename: {filename}\n" f"Patch:\n{patch}\n" f"{'-' * 40}")
"""