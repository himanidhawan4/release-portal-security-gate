from src import github_client
from detect_secrets.settings import transient_settings
from detect_secrets.core import scan
import json


def check_secrets_in_pr(pr_url, include_details=False):

    reasons = {
        "Artifactory Credentials": "Exposed Artifactory credentials can provide unauthorized access to private package repositories and stored artifacts.",
        "AWS Access Key": "Exposed AWS credentials can allow unauthorized access to AWS resources and services within the permissions assigned to the credentials.",
        "Azure Storage Key": "An exposed Azure Storage key can provide access to an Azure Storage account and its permitted operations.",
        "Basic Auth Credentials": "Exposed Basic Authentication credentials can allow an attacker to authenticate to a protected service using the discovered credentials.",
        "Cloudant Credentials": "Exposed Cloudant credentials can provide unauthorized access to databases and application data.",
        "Discord Bot Token": "An exposed Discord bot token can allow an attacker to take control of the associated bot and perform actions available to it.",
        "GitHub Token": "An exposed GitHub token can allow unauthorized access to GitHub resources according to its assigned permissions.",
        "GitLab Token": "An exposed GitLab token can allow unauthorized access to GitLab resources and API operations.",
        "IBM Cloud IAM Token": "An exposed IBM Cloud IAM token can provide unauthorized access to IBM Cloud resources according to its permissions.",
        "IBM COS HMAC Credentials": "Exposed IBM Cloud Object Storage HMAC credentials can allow unauthorized access to storage operations.",
        "IP Address": "An exposed public IP address can reveal infrastructure information and may help attackers identify reachable services.",
        "JWT": "An exposed JWT may allow an attacker to impersonate the identity represented by the token while it remains valid.",
        "Secret Keyword": "A Secret Keyword finding indicates terminology commonly associated with sensitive information such as passwords, tokens, API keys, or credentials.",
        "Mailchimp API Key": "An exposed Mailchimp API key can provide unauthorized access to Mailchimp resources according to its assigned permissions.",
        "NPM Token": "An exposed NPM token can allow unauthorized package publishing and create a software supply-chain risk.",
        "OpenAI API Key": "An exposed OpenAI API key can allow unauthorized API usage, potentially causing service misuse or unexpected charges.",
        "Private Key": "An exposed private key can allow an attacker to impersonate an identity or authenticate to systems that trust the key.",
        "PyPI Token": "An exposed PyPI token can allow unauthorized package publishing and create a software supply-chain risk.",
        "SendGrid API Key": "An exposed SendGrid API key can allow unauthorized use of email and other SendGrid services.",
        "Slack Token": "An exposed Slack token can allow unauthorized access to Slack resources according to its assigned permissions.",
        "SoftLayer Credentials": "Exposed SoftLayer credentials can provide unauthorized access to cloud infrastructure and associated resources.",
        "Square OAuth Token": "An exposed Square OAuth token can provide unauthorized access to Square resources and permitted operations.",
        "Stripe API Key": "An exposed Stripe API key can allow unauthorized access to Stripe resources and operations.",
        "Telegram Bot Token": "An exposed Telegram bot token can allow an attacker to take control of the associated bot.",
        "Twilio API Key": "An exposed Twilio API key can allow unauthorized use of Twilio services and potentially generate unexpected charges.",
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

        for filename, patch_text in data["changed_files"]:

            patch = patch_text.splitlines()
            lineno = 0

            for line in patch:

                if line.startswith("@@"):

                    parts = line.split(" ")

                    for item in parts:

                        if item.startswith("+"):

                            item = item.split(",")

                            try:
                                lineno = int(item[0][1:])
                            except ValueError:
                                lineno = 0

                    continue

                if line.startswith(("+++", "---")):
                    continue

                if line.startswith("-"):
                    continue

                if line.startswith(" "):
                    lineno += 1
                    continue

                if line.startswith("+"):

                    added_line = line[1:]

                    result.append(
                        (
                            filename,
                            added_line,
                            lineno,
                        )
                    )

                    lineno += 1

        findings_result = []

        for filename, line, lineno in result:

            findings = scan.scan_line(line)

            if not findings:
                continue

            for finding in findings:

                findings_result.append(
                    {
                        "file": filename,
                        "line": lineno,
                        "issue": finding.type,
                    }
                )

        if not findings_result:

            print("\nNo secrets detected.")

            return []

        verdict = []

        for finding in findings_result:

            issue = finding["issue"]

            verdict_item = {
                "file": finding["file"],
                "line": finding["line"],
                "issue": issue,
                "severity": "CRITICAL",
                "reason": reasons.get(
                    issue,
                    "This finding may expose sensitive information or credentials and should be reviewed carefully.",
                ),
                "verdict": "BLOCK",
            }

            if include_details:

                verdict_item["recommendation"] = (
                    "Remove the secret from the code and rotate or revoke "
                    "the credential if it is valid. Use a secure secret "
                    "management mechanism or protected environment variable "
                    "instead of storing credentials directly in source code."
                )

            verdict.append(verdict_item)

        print("\nFinal Verdict")
        print("=============")
        print(json.dumps(verdict, indent=2))

        return verdict
