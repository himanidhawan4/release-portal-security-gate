import sys
import requests
from dotenv import load_dotenv
import os

load_dotenv()


def fetch_pr_details(pr_url):
    parts = pr_url.split("/")
    if "pull" not in parts:
        print(
            "Error: Invalid GitHub Pull Request URL. Missing '/pull/'.", file=sys.stderr
        )
        return []

    pull_number = parts[parts.index("pull") + 1]
    owner = parts[3]
    repo = parts[4]
    github_token = os.getenv("GITHUB_TOKEN")

    if github_token:
        print("GitHub token loaded successfully")
    else:
        print("GitHub token NOT loaded")

    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
    }

    requestapi = (
        f"https://api.github.com/repos/{owner}/{repo}/pulls/{pull_number}/files"
    )
    print("requested api url is: ")
    print(requestapi)

    response = requests.get(requestapi, headers=headers)

    if response.status_code == 401:
        print("Error 401: GitHub token is invalid, expired, or revoked.")
        return []

    if response.status_code == 403:
        print(
            "Error 403: GitHub token is valid, but does not have sufficient permission."
        )
        return []

    if response.status_code != 200:
        print("Error:", response.status_code, response.text)
        return []

    details = []
    for i in response.json():
        filename = i.get("filename") or "No filename available"
        patch = i.get("patch") or "No patch available"
        details.append((filename, patch))

    return details


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python github_client.py <GitHub Pull Request URL>")
        sys.exit(1)

    pr_url = sys.argv[1]
    pr_details = fetch_pr_details(pr_url)
    print("PR Details are fetched carefully check everything :")
    for filename, patch in pr_details:
        print(f"Filename: {filename}\nPatch:\n{patch}\n{'-'*40}")
