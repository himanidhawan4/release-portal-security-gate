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
    dependency_ecosystems = {
        "package.json": "npm",
        "package-lock.json": "npm",
        "npm-shrinkwrap.json": "npm",
        "requirements.txt": "PyPI",
        "pyproject.toml": "PyPI",
        "pipfile": "PyPI",
        "pipfile.lock": "PyPI",
        "go.mod": "Go",
        "go.sum": "Go",
        "pom.xml": "Maven",
        "build.gradle": "Maven",
        "build.gradle.kts": "Maven",
        "cargo.toml": "crates.io",
        "cargo.lock": "crates.io",
        "gemfile": "RubyGems",
        "gemfile.lock": "RubyGems",
        "composer.json": "Packagist",
        # Test files in your current repository
        "dependencies-nested.json": "PyPI",
        "dependencies-simple.json": "PyPI",
    }
    for file, patch_details in details:
        filename = file
        patch = patch_details
        lineno = None
        # ------------------------FILE SCANING BEGINS HERE----------------------------------------------------------------------------------------------
        if filename.lower() in dependency_ecosystems:
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
                                    result.append((filename, name, version, lineno))
                                    break

                        lineno += 1

                    elif line.startswith(" "):
                        lineno += 1
            else:
                patch = patch.splitlines()
                lineno = None
                searching_era = []
                findings = []
                dependency_lines = {}
                for line in patch:
                    if line.startswith("@@"):
                        line = line.split(" ")
                        for i in line:
                            if i.startswith("+"):
                                i = i.split(",")
                                lineno = int(i[0][1:])
                    elif line.startswith(("+++", "---")):
                        continue
                    elif line.startswith(("-")):
                        continue
                    elif line.startswith("+"):
                        line = line[1:].strip()
                        lineno += 1
                        searching_era.append(line)

                        if line.endswith('": {') or '": "' in line:
                            name = line.split('"')[1]
                            dependency_lines[name] = lineno
                json_text = "\n".join(searching_era)
                try:
                    data = json.loads(json_text)
                except json.JSONDecodeError:
                    continue
                if "dependencies" in data:
                    dependencies = data["dependencies"]

                    for name, details in dependencies.items():
                        lineno = dependency_lines.get(name)

                        if isinstance(details, dict):
                            version = details["version"]
                        else:
                            version = details

                        findings.append((filename, name, version, lineno))

                else:
                    for name, version in data.items():
                        if name in dependency_lines:
                            findings.append(
                                (filename, name, version, dependency_lines[name])
                            )
                result.extend(findings)
    print("FINAL RESULT:", result)
    osv_results = []

    for filename, name, version, lineno in result:
        filename_lower = filename.lower()
        ecosystem = dependency_ecosystems.get(filename_lower)

        if ecosystem is None:
            continue

        data = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
        response = requests.post("https://api.osv.dev/v1/query", json=data)
        response_data = response.json()
        for vuln in response_data.get("vulns", []):
            fixed_versions = []

            for affected in vuln.get("affected", []):
                for range_data in affected.get("ranges", []):
                    for event in range_data.get("events", []):
                        if event.get("fixed"):
                            fixed_versions.append(event["fixed"])
            solution_text = (
                f"Upgrade {name} to version {fixed_versions[0]} or later."
                if fixed_versions
                else f"Review security advisory for {name}."
            )

            vulnerabilities.append(
                {
                    "id": vuln.get("id"),
                    "summary": vuln.get("summary"),
                    "severity": vuln.get("database_specific", {}).get("severity"),
                    "reason": vuln.get("details") or vuln.get("summary"),
                    "solution": solution_text,
                }
            )

        osv_results.append(
            {
                "filename": filename,
                "package": name,
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
