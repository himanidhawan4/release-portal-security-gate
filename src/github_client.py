import sys
import requests
import os
from dotenv import load_dotenv

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
    requestapi = (
        f"https://api.github.com/repos/{owner}/{repo}/pulls/{pull_number}/files"
    )
    github_token = os.getenv("GITHUB_TOKEN")

    headers = {
        "Authorization": f"Bearer {github_token}",
        "Accept": "application/vnd.github+json",
    }
    response = requests.get(requestapi, headers=headers)
    if response.status_code != 200:
        print("Error:", response.status_code, response.text)
        return []

    details = []
    for i in response.json():
        filename = i.get("filename") or "No filename available"
        patch = i.get("patch") or "No patch available"
        details.append((filename, patch))
    return details
