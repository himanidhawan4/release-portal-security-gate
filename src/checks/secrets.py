from src import github_client
import sys
from detect_secrets.settings import transient_settings
from detect_secrets.core import scan
import json

# python -m detect_secrets scan --list-all-plugins
# python -m src.checks.secrets https://github.com/himanidhawan4/release-portal-security-gate-test/pull/1


def check_secrets_in_pr(pr_url):

    importance = {
        "Artifactory Credentials": (
            "Exposed Artifactory credentials can provide unauthorized access to "
            "private package repositories and stored artifacts. Depending on the "
            "permissions assigned to the credentials, an attacker could download "
            "confidential packages, upload malicious artifacts, or modify existing "
            "packages. This can create both data exposure and software supply-chain "
            "risks, making the credentials a serious security concern."
        ),
        "AWS Access Key": (
            "Exposed AWS credentials can allow unauthorized access to AWS resources "
            "and services within the permissions assigned to the credentials. "
            "Depending on those permissions, an attacker could access sensitive "
            "data, modify cloud infrastructure, create or delete resources, or "
            "generate unexpected cloud costs. A compromised AWS credential should "
            "be treated as exposed and revoked or rotated immediately."
        ),
        "Azure Storage Key": (
            "An exposed Azure Storage key can provide access to an Azure Storage "
            "account and the operations permitted by that key. Depending on the "
            "configuration, an attacker could read, modify, upload, or delete "
            "stored data. Because storage keys can provide broad access to storage "
            "resources, a compromised key should be considered exposed and rotated "
            "immediately."
        ),
        "Basic Auth Credentials": (
            "Exposed Basic Authentication credentials can allow an attacker to "
            "authenticate directly to a protected service using the discovered "
            "username and password. If the credentials remain valid, the attacker "
            "could access resources available to that account and potentially use "
            "the account as a starting point for further attacks. The credentials "
            "should therefore be changed or revoked immediately."
        ),
        "Cloudant Credentials": (
            "Exposed Cloudant credentials can provide unauthorized access to "
            "Cloudant databases and application data. Depending on the assigned "
            "permissions, an attacker may be able to read, modify, or delete "
            "database records. This can result in sensitive data exposure, data "
            "manipulation, or disruption of applications relying on the database."
        ),
        "Discord Bot Token": (
            "An exposed Discord bot token can allow an attacker to take control "
            "of the associated bot. Depending on the bot's permissions, the "
            "attacker could interact with servers, channels, users, or other "
            "Discord resources available to the bot. The token should be treated "
            "as compromised and regenerated immediately."
        ),
        "GitHub Token": (
            "An exposed GitHub token can allow unauthorized access to GitHub "
            "resources according to the permissions assigned to that token. "
            "Depending on its scope, an attacker could access private repositories, "
            "source code, issues, pull requests, or perform unauthorized API "
            "operations. The token should be revoked immediately and replaced "
            "with a securely managed credential if continued access is required."
        ),
        "GitLab Token": (
            "An exposed GitLab token can allow unauthorized access to GitLab "
            "resources and API operations permitted by the token. Depending on "
            "its scope, an attacker could access private repositories, source "
            "code, CI/CD resources, or perform unauthorized repository operations. "
            "The token should be revoked immediately and replaced if necessary."
        ),
        "IBM Cloud IAM Token": (
            "An exposed IBM Cloud IAM token can provide unauthorized access to "
            "IBM Cloud resources according to the permissions assigned to the "
            "token. An attacker could potentially access services, retrieve "
            "sensitive information, or modify cloud resources. The token should "
            "be revoked or rotated immediately to prevent unauthorized cloud "
            "activity."
        ),
        "IBM COS HMAC Credentials": (
            "Exposed IBM Cloud Object Storage HMAC credentials can allow unauthorized "
            "access to object-storage operations associated with the credentials. "
            "Depending on their permissions, an attacker could access, upload, "
            "modify, or delete stored objects. These credentials should be treated "
            "as compromised and rotated immediately."
        ),
        "IP Address": (
            "An exposed public IP address is not necessarily a credential or direct "
            "authentication secret, but it can reveal information about application "
            "infrastructure. Attackers may use the address to identify exposed "
            "services, perform reconnaissance, and look for vulnerabilities. The "
            "actual security impact depends on which services are reachable and "
            "how the infrastructure is secured."
        ),
        "JWT": (
            "An exposed JWT may allow an attacker to impersonate the identity "
            "represented by the token while it remains valid. The attacker could "
            "potentially access protected application resources or perform actions "
            "using the permissions contained in the token. The affected token or "
            "session should be invalidated where possible and a new token should "
            "be issued."
        ),
        "Secret Keyword": (
            "A Secret Keyword finding indicates that a line contains terminology "
            "commonly associated with sensitive information such as passwords, "
            "tokens, API keys, or credentials. Keyword detection can sometimes "
            "produce false positives because the presence of a keyword does not "
            "prove that an actual secret exists. However, the value should be "
            "reviewed carefully and, if it is a real credential, removed and "
            "rotated or revoked."
        ),
        "Mailchimp API Key": (
            "An exposed Mailchimp API key can provide unauthorized access to "
            "Mailchimp resources according to the permissions associated with "
            "the key. This could potentially expose subscriber information, "
            "campaign data, or allow unauthorized account operations. The "
            "compromised key should be revoked and replaced to prevent further "
            "unauthorized API activity."
        ),
        "NPM Token": (
            "An exposed NPM token can allow unauthorized access to NPM operations "
            "permitted by the token. If the token has publishing permissions, "
            "an attacker could potentially publish malicious package versions "
            "and distribute harmful code to downstream users. This creates a "
            "significant software supply-chain risk, so the token should be "
            "revoked immediately."
        ),
        "OpenAI API Key": (
            "An exposed OpenAI API key can allow unauthorized parties to consume "
            "API services using the associated account. This may result in "
            "unexpected API usage, financial charges, or misuse of available "
            "services. The compromised key should be revoked immediately and "
            "replaced with a securely managed credential if continued access "
            "is required."
        ),
        "Private Key": (
            "An exposed private key can allow an attacker to impersonate the "
            "identity associated with that key or authenticate to systems that "
            "trust it. Depending on its purpose, the key could provide access "
            "to servers, applications, certificates, or other protected resources. "
            "A private key should be considered compromised once exposed and "
            "should be replaced immediately."
        ),
        "PyPI Token": (
            "An exposed PyPI token can allow unauthorized package publishing "
            "using the permissions associated with the token. An attacker could "
            "potentially publish malicious versions of packages and affect "
            "applications that depend on those packages. This creates a software "
            "supply-chain risk, so the token should be revoked and replaced "
            "immediately."
        ),
        "SendGrid API Key": (
            "An exposed SendGrid API key can allow unauthorized use of email "
            "and other SendGrid services permitted by the key. An attacker "
            "could potentially send unauthorized messages, abuse the account, "
            "or access available resources. The key should be revoked immediately "
            "and replaced with a securely managed credential."
        ),
        "Slack Token": (
            "An exposed Slack token can allow unauthorized access to Slack "
            "resources according to the permissions assigned to the token. "
            "Depending on its scope, an attacker could access messages, channels, "
            "files, or perform actions on behalf of the associated application "
            "or user. The token should be revoked immediately."
        ),
        "SoftLayer Credentials": (
            "Exposed SoftLayer credentials can provide unauthorized access to "
            "cloud infrastructure and associated resources. Depending on the "
            "privileges assigned to the credentials, an attacker could access "
            "systems, modify infrastructure, or retrieve sensitive information. "
            "The credentials should be revoked or rotated immediately."
        ),
        "Square OAuth Token": (
            "An exposed Square OAuth token can provide unauthorized access to "
            "Square resources and operations permitted by the token. Depending "
            "on its scope, this may expose business or payment-related information "
            "or allow unauthorized account operations. The token should be revoked "
            "immediately to prevent continued unauthorized access."
        ),
        "Stripe API Key": (
            "An exposed Stripe API key can allow unauthorized access to Stripe "
            "resources and operations permitted by the key. Depending on its "
            "permissions, an attacker could potentially access payment-related "
            "information or perform unauthorized account operations. The key "
            "should be revoked immediately and replaced with a securely managed "
            "credential."
        ),
        "Telegram Bot Token": (
            "An exposed Telegram bot token can allow an attacker to take control "
            "of the associated bot. The attacker may be able to send messages, "
            "interact with users or groups, and perform other operations available "
            "to the bot. The token should be regenerated immediately so the "
            "compromised token can no longer be used."
        ),
        "Twilio API Key": (
            "An exposed Twilio API key can allow unauthorized use of Twilio "
            "services and resources permitted by the key. Depending on the "
            "permissions, an attacker could abuse communication services, access "
            "associated resources, or generate unexpected charges. The key should "
            "be revoked immediately and replaced with a securely managed "
            "credential."
        ),
    }

    result = []

    with transient_settings(
        {
            "plugins_used": [
                {"name": "ArtifactoryDetector"},
                {"name": "AWSKeyDetector"},
                {"name": "AzureStorageKeyDetector"},
                {"name": "BasicAuthDetector"},
                {"name": "CloudantDetector"},
                {"name": "DiscordBotTokenDetector"},
                {"name": "GitHubTokenDetector"},
                {"name": "GitLabTokenDetector"},
                {"name": "IbmCloudIamDetector"},
                {"name": "IbmCosHmacDetector"},
                {"name": "IPPublicDetector"},
                {"name": "JwtTokenDetector"},
                {"name": "KeywordDetector"},
                {"name": "MailchimpDetector"},
                {"name": "NpmDetector"},
                {"name": "OpenAIDetector"},
                {"name": "PrivateKeyDetector"},
                {"name": "PypiTokenDetector"},
                {"name": "SendGridDetector"},
                {"name": "SlackDetector"},
                {"name": "SoftlayerDetector"},
                {"name": "SquareOAuthDetector"},
                {"name": "StripeDetector"},
                {"name": "TelegramBotTokenDetector"},
                {"name": "TwilioKeyDetector"},
            ]
        }
    ):

        data = github_client.fetch_pr_details(pr_url)

        if not data:
            return []

        for file, patchs in data["changed_files"]:
            filename = file
            patch = patchs.splitlines()

            for line in patch:

                if line.startswith("@@"):
                    line = line.split(" ")

                    for i in line:
                        if i.startswith("+"):
                            i = i.split(",")
                            lineno = int(i[0][1:])

                    continue

                elif line.startswith(("+++", "---")):
                    continue

                elif line.startswith("-"):
                    continue

                elif line.startswith(" "):
                    lineno += 1
                    continue

                elif line.startswith("+"):
                    line = line[1:]
                    result.append((filename, line, lineno))
                    lineno += 1

        # Collect all detected secrets first.
        findings_result = []

        for filename, line, lineno in result:
            findings = scan.scan_line(line)

            if not findings:
                continue

            for finding in findings:
                findings_result.append(
                    {
                        "FileName": filename,
                        "Line_Number": lineno,
                        "Type": finding.type,
                    }
                )

        # If nothing was detected, finish immediately.
        if not findings_result:
            print("\nNo secrets detected.")
            return []

        # Ask only once for additional information.
        print(
            "\nDo you want importance and recommendations "
            "along with the final verdict? (y/n): ",
            end="",
        )

        while True:
            need = input().strip().lower()

            if need == "y" or need == "n":
                break

            print("Invalid input. Please enter 'y' or 'n': ", end="")

        verdict = []

        for finding in findings_result:

            verdict_item = {
                "FileName": finding["FileName"],
                "Line_Number": finding["Line_Number"],
                "Type": finding["Type"],
                "Severity": "Critical",
                "Verdict": "Block",
            }

            if need == "y":
                verdict_item["Importance"] = importance.get(
                    finding["Type"],
                    (
                        "This finding may expose sensitive information or "
                        "credentials. The detected value should be reviewed "
                        "carefully to determine whether it represents a valid "
                        "secret or credential."
                    ),
                )

                verdict_item["Recommended_Action"] = (
                    "Remove the secret from the code and rotate or revoke the "
                    "credential if it is valid. Avoid committing credentials "
                    "directly to source code and use a secure secret-management "
                    "mechanism or protected environment variable instead."
                )

            verdict.append(verdict_item)

        print("\nFinal Verdict")
        print("=============")
        print(json.dumps(verdict, indent=2))

        return verdict


"""
if __name__ == "__main__":
    if len(sys.argv) > 1:
        pr_url = sys.argv[1]
        result = check_secrets_in_pr(pr_url)
    else:
        print("Usage: python <script> <GitHub PR URL>")
"""
