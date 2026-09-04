import sys
import requests
from dotenv import load_dotenv
import os

load_dotenv()


def fetch_pr_details(pr_url):
    parts = pr_url.rstrip("/").split("/")

    if "pull" not in parts:
        print(
            "Error: Invalid GitHub Pull Request URL. Missing '/pull/'.",
            file=sys.stderr,
        )
        return None

    try:
        pull_index = parts.index("pull")
        pull_number = parts[pull_index + 1]
        owner = parts[3]
        repo = parts[4]
    except (ValueError, IndexError):
        print(
            "Error: Invalid GitHub Pull Request URL.",
            file=sys.stderr,
        )
        return None

    github_token = os.getenv("GITHUB_TOKEN")

    if github_token:
        print("GitHub token loaded successfully")
    else:
        print("GitHub token NOT loaded")

    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
    }

    pr_api_url = (
        f"https://api.github.com/repos/"
        f"{owner}/{repo}/pulls/{pull_number}"
    )

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
            "Error 401: GitHub token is invalid, expired, or revoked."
        )
        return None

    if response.status_code == 403:
        print(
            "Error 403: GitHub token is valid, but does not have sufficient permission."
        )
        return None

    if response.status_code != 200:
        print(
            "Error:",
            response.status_code,
            response.text,
        )
        return None

    pr_data = response.json()

    files_api_url = (
        f"https://api.github.com/repos/"
        f"{owner}/{repo}/pulls/{pull_number}/files"
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

    return {
        "owner": owner,
        "repo": repo,
        "pull_number": pull_number,
        "head_sha": pr_data["head"]["sha"],
        "clone_url": pr_data["head"]["repo"]["clone_url"],
        "changed_files": changed_files,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(
            "Usage: python github_client.py "
            "<GitHub Pull Request URL>"
        )
        sys.exit(1)

    pr_url = sys.argv[1]

    pr_details = fetch_pr_details(pr_url)

    if not pr_details:
        sys.exit(1)

    print(
        "PR Details are fetched carefully. "
        "Check everything:"
    )

    print(
        f"Repository: "
        f"{pr_details['owner']}/{pr_details['repo']}"
    )

    print(
        f"Pull Request: "
        f"{pr_details['pull_number']}"
    )

    print(
        f"Head SHA: "
        f"{pr_details['head_sha']}"
    )

    for filename, patch in pr_details["changed_files"]:
        print(
            f"Filename: {filename}\n"
            f"Patch:\n{patch}\n"
            f"{'-' * 40}"
        )