import re
import src.github_client as github_client
import sys
import json


def check_wildcards(pr_url):
    hunk_pattern = r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@"
    action_wildcard_pattern = r'\s*"?\s*Action\s*"?\s*(=|:)\s*"\*"'
    resource_wildcard_pattern = r'\s*"?\s*Resource\s*"?\s*(=|:)\s*"\*"'
    findings = []
    choice = input(
        "Do you want importance and recommendation for IAM wildcards? (y/n): "
    ).lower()

    while choice not in ("y", "n"):
        choice = input("Please choose y or n: ").lower()
    importance = {
        "IAM wildcard Action": {
            "importance": (
                "Critical severity: Using Action='*' grants extremely broad AWS API "
                "permissions instead of limiting the identity to the specific operations "
                "required by the application. The Action element defines which AWS API "
                "operations a principal is allowed to perform, and '*' can represent "
                "all actions supported by the applicable policy context. This can violate "
                "the principle of least privilege and significantly increase the blast "
                "radius of a compromised IAM user, role, workload, or access key. "
                "Depending on the resources, conditions, and other policy statements, "
                "broad action permissions may allow an identity to read, create, modify, "
                "or delete resources and may also permit security-sensitive operations "
                "such as changing configurations or permissions. The actual impact "
                "depends on the complete IAM policy, AWS service, Resource element, "
                "Condition elements, and applicable identity or resource policies. "
                "Action='*' should therefore be treated as a critical finding and "
                "requires explicit justification in exceptional cases."
            ),
            "recommendation": (
                "Replace Action='*' with the smallest set of specific AWS API actions "
                "required by the workload. Start by identifying exactly what the "
                "application needs to do, then grant only those operations, for example "
                "s3:GetObject instead of s3:* or Action='*'. Where multiple operations "
                "are genuinely required, list only those required actions rather than "
                "using a service-wide or account-wide wildcard. Review whether actions "
                "that modify, delete, create, or change permissions are actually needed. "
                "Combine specific actions with narrowly scoped Resource ARNs and "
                "appropriate Condition keys wherever supported. Use IAM Access Analyzer "
                "to identify unused or excessive permissions, review CloudTrail activity "
                "to understand which API operations are actually being used, and "
                "periodically reduce the policy as application requirements change. "
                "For advanced least-privilege designs, separate permissions by workload "
                "or role, avoid mixing unrelated privileges in one policy, use temporary "
                "credentials where appropriate, and apply permission boundaries or "
                "organization-level controls as additional guardrails. Do not rely on "
                "a wildcard merely because the current Resource is restricted; minimize "
                "both the allowed actions and their resource scope."
            ),
        },
        "IAM wildcard Resource": {
            "importance": (
                "High severity: Using Resource='*' allows the specified IAM actions to "
                "potentially apply to all resources covered by those actions instead of "
                "restricting access to the specific resources required by the workload. "
                "The Resource element defines which AWS resources a permission applies "
                "to, so a wildcard can significantly broaden the scope of an otherwise "
                "specific action. For example, allowing s3:GetObject on '*' may permit "
                "access to objects beyond the application's intended bucket or data "
                "scope. This can increase the blast radius of a compromised identity "
                "and violates the principle of least privilege when narrower resource "
                "permissions are available. The exact security impact depends on the "
                "actions being granted and whether the relevant AWS service supports "
                "resource-level permissions. Some AWS actions legitimately require "
                "Resource='*' because they do not support resource-level restriction, "
                "so the wildcard must be evaluated in the context of the specific "
                "AWS service and action rather than being considered universally unsafe."
            ),
            "recommendation": (
                "Replace Resource='*' with the narrowest specific resource ARN or "
                "resource scope required by the application whenever the AWS service "
                "supports resource-level permissions. For example, instead of granting "
                "s3:GetObject on all applicable resources, restrict the permission to "
                "the required S3 bucket and object path. Review the AWS service's IAM "
                "documentation to determine whether the action supports resource-level "
                "permissions and which ARN formats are valid. Combine resource "
                "restrictions with specific Action values and Condition keys such as "
                "resource tags, prefixes, VPC restrictions, encryption requirements, "
                "or other service-supported controls where appropriate. Use IAM Access "
                "Analyzer to identify overly broad resource access and periodically "
                "review policies as application requirements change. Do not blindly "
                "replace every Resource='*': some AWS actions require '*' because they "
                "operate at the account, region, or service level. In those cases, "
                "keep the wildcard only when required by AWS and compensate with the "
                "narrowest possible actions and appropriate conditions."
            ),
        },
    }
    details = github_client.fetch_pr_details(pr_url)

    if not details:
        return []

    for file, patchs in details["changed_files"]:
        filename = file
        patch = patchs
        lineno = None

        if filename.lower().endswith((".tf", ".json")):
            patch = patch.splitlines()

            for line in patch:
                if line.startswith("@@"):
                    hunk_match = re.match(hunk_pattern, line)

                    if hunk_match:
                        lineno = int(hunk_match.group(1))
                    continue

                if line.startswith(("+++", "---")):
                    continue

                if line.startswith("-"):
                    continue

                if lineno is None:
                    continue

                elif line.startswith(" "):
                    lineno += 1

                elif line.startswith("+"):
                    content = line[1:]

                    if content.lstrip().startswith(("#", "//")):
                        # Skip comment lines
                        lineno += 1
                        continue

                    if re.match(action_wildcard_pattern, content):
                        if choice == "n":
                            findings.append(
                                {
                                    "file": filename,
                                    "line": lineno,
                                    "issue": "IAM wildcard Action",
                                    "match": content.strip(),
                                }
                            )
                        elif choice == "y":
                            findings.append(
                                {
                                    "file": filename,
                                    "line": lineno,
                                    "issue": "IAM wildcard Action",
                                    "match": content.strip(),
                                    "Importance": importance["IAM wildcard Action"][
                                        "importance"
                                    ],
                                    "Recommendation": importance["IAM wildcard Action"][
                                        "recommendation"
                                    ],
                                }
                            )

                    elif re.match(resource_wildcard_pattern, content):
                        if choice == "n":
                            findings.append(
                                {
                                    "file": filename,
                                    "line": lineno,
                                    "issue": "IAM wildcard Resource",
                                    "match": content.strip(),
                                }
                            )
                        elif choice == "y":
                            findings.append(
                                {
                                    "file": filename,
                                    "line": lineno,
                                    "issue": "IAM wildcard Resource",
                                    "match": content.strip(),
                                    "Importance": importance["IAM wildcard Resource"][
                                        "importance"
                                    ],
                                    "Recommendation": importance[
                                        "IAM wildcard Resource"
                                    ]["recommendation"],
                                }
                            )
                    lineno += 1

    print("\n===== IAM WILDCARD SCAN SUMMARY =====")
    print(f"Files checked: {len(details)}")
    print(f"Wildcard findings: {len(findings)}")

    if findings:
        print("Result: BLOCK")
    else:
        print("Result: PASS")

    print("\n===== JSON RESULT =====")

    print(json.dumps(findings, indent=2))

    return findings


if __name__ == "__main__":
    check_wildcards(sys.argv[1])
