import src.github_client as github_client
import sys
import requests
import json

"""
https://github.com/himanidhawan4/release-portal-security-gate-test/pull/3
python -m src.checks.cve https://github.com/himanidhawan4/release-portal-security-gate-test/pull/3

"""


def check_vulnerabilities(pr_url):
    details = github_client.fetch_pr_details(pr_url)
    result = []
    vulnerabilities = []
    for file, patch_details in details:
        filename = file
        patch = patch_details
        lineno = None
        if filename.lower().endswith((".json", ".txt")):
            if filename.lower().endswith(".txt"):
                patch = patch.splitlines()
                for line in patch:

                    if line.startswith("@@"):
                        line = line.split(" ")
                        for i in line:
                            if i.startswith("+"):
                                i = i.split(",")
                                lineno = int(i[0][1:])

                        continue
                    elif line.startswith(("---", "+++")):
                        continue
                    elif line.startswith(("-")):
                        continue
                    elif line.startswith("+"):
                        line = line[1:]
                        if line and not line.startswith("#"):
                            for i in ("==", ">=", "<=", "~=", ">", "<"):
                                if i in line:
                                    line = line.split(i)
                                    name = line[0]
                                    version = line[1]
                                    result.append((filename, name, i, version, lineno))
                                    break

                        lineno += 1

                    elif line.startswith(" "):
                        lineno += 1
            else:
                pass
    osv_results = []
    for filename, name, i, version, lineno in result:
        data = {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
        response = requests.post("https://api.osv.dev/v1/query", json=data)
        response = response.json()

        for vuln in response.get("vulns", []):
            fixed_versions = []

            for affected in vuln.get("affected", []):
                for range_data in affected.get("ranges", []):
                    for event in range_data.get("events", []):
                        if event.get("fixed"):
                            fixed_versions.append(event["fixed"])

            vulnerabilities.append(
                {
                    "id": vuln.get("id"),
                    "summary": vuln.get("summary"),
                    "severity": vuln.get("database_specific", {}).get("severity"),
                    "reason": vuln.get("details") or vuln.get("summary"),
                    "solution": f"Upgrade {name} to version {fixed_versions[0]} or later.",
                }
            )

        osv_results.append(
            {
                "filename": filename,
                "package": name,
                "operator": i,
                "version": version,
                "line": lineno,
            }
        )
    while True:
        choice = input("Do you want to see solution and reasons for your verdict ??")
        if choice.lower() == "y":
            for i in vulnerabilities:
                print(json.dumps(i, indent=2))
            break

        elif choice.lower() == "n":
            for i in osv_results:
                print(json.dumps(i, indent=2))
            break
        else:
            print("Choose either y or n")
            continue


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python github_client.py <GitHub Pull Request URL>")
        sys.exit(1)
    pr_url = sys.argv[1]
    pr_details = check_vulnerabilities(pr_url)
