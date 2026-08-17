import sys
import requests


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
    print("requested api url is: ")
    print(requestapi)

    response = requests.get(requestapi)
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
