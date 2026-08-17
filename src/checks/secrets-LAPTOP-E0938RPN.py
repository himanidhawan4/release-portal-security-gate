from src import github_client
import sys
from detect_secrets.settings import transient_settings
from detect_secrets.core import scan
import json

# python -m detect_secrets scan --list-all-plugins
# python -m src.checks.secrets https://github.com/himanidhawan4/release-portal-security-gate-test/pull/1


def check_secrets_in_pr(pr_url):
    importance = {
        "Artifactory Credentials": "Exposed Artifactory credentials can allow unauthorized access to private packages, artifacts, and repositories.",
        "AWS Access Key": "Exposed AWS credentials can allow unauthorized access to AWS resources and services within the credential's permissions.",
        "Azure Storage Key": "Exposed Azure Storage keys can allow unauthorized access to storage accounts and potentially sensitive stored data.",
        "Basic Auth Credentials": "Exposed Basic Authentication credentials can allow attackers to authenticate directly to protected services.",
        "Cloudant Credentials": "Exposed Cloudant credentials can allow unauthorized access to databases and potentially sensitive application data.",
        "Discord Bot Token": "An exposed Discord bot token can allow unauthorized control of the bot and actions available to it.",
        "GitHub Token": "An exposed GitHub token can allow unauthorized access to repositories, APIs, and other GitHub resources permitted by the token.",
        "GitLab Token": "An exposed GitLab token can allow unauthorized access to repositories, APIs, and other GitLab resources permitted by the token.",
        "IBM Cloud IAM Token": "An exposed IBM Cloud IAM token can allow unauthorized access to IBM Cloud resources according to its assigned permissions.",
        "IBM COS HMAC Credentials": "Exposed IBM Cloud Object Storage HMAC credentials can allow unauthorized access to stored objects and storage operations.",
        "IP Address": "An exposed public IP address can reveal infrastructure details and help attackers identify systems or services for further targeting.",
        "JWT": "An exposed JWT may allow attackers to impersonate the associated identity and access protected application resources until it expires or is revoked.",
        "Secret Keyword": "This finding may indicate that passwords, tokens, credentials, or other sensitive information has been committed to the repository.",
        "Mailchimp API Key": "An exposed Mailchimp API key can allow unauthorized access to account resources, including potentially sensitive subscriber or campaign data.",
        "NPM Token": "An exposed NPM token can allow unauthorized package access or publishing, potentially enabling malicious changes to packages.",
        "OpenAI API Key": "An exposed OpenAI API key can allow unauthorized API usage and may result in unexpected consumption and associated costs.",
        "Private Key": "An exposed private key can enable impersonation, unauthorized authentication, or access to systems and data protected by the corresponding key.",
        "PyPI Token": "An exposed PyPI token can allow unauthorized package publishing and potentially enable malicious versions of packages to be distributed.",
        "SendGrid API Key": "An exposed SendGrid API key can allow unauthorized email operations and potential abuse of the associated account.",
        "Slack Token": "An exposed Slack token can allow unauthorized access to Slack resources and actions permitted by the token.",
        "SoftLayer Credentials": "Exposed SoftLayer credentials can allow unauthorized access to cloud infrastructure and resources associated with the account.",
        "Square OAuth Token": "An exposed Square OAuth token can allow unauthorized access to Square resources and operations permitted by the token.",
        "Stripe API Key": "An exposed Stripe API key can allow unauthorized access to payment-related resources and operations permitted by the key.",
        "Telegram Bot Token": "An exposed Telegram bot token can allow unauthorized control of the bot and actions available through its account.",
        "Twilio API Key": "An exposed Twilio API key can allow unauthorized use of communication services and other Twilio resources permitted by the key.",
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
        for file, patchs in data:
            filename = file
            patch = patchs.splitlines()
            print("------------------")
            for line in patch:
                if line.startswith("@@"):
                    line = line.split(" ")
                    print(line)
                    for i in line:
                        if i.startswith("+"):
                            i = i.split(",")
                            lineno = int(i[0][1:])
                    print(lineno)
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
                    lineno = lineno + 1
        verdict = []
        for filename, line, lineno in result:
            findings = scan.scan_line(line)
            for finding in findings:
                verdict.append(
                    {
                        "FileName": filename,
                        "Line_Number": lineno,
                        "Type": finding.type,
                        "Importance": importance.get(
                            finding.type,
                            "This finding may expose sensitive information or credentials.",
                        ),
                        "Severity": "Critical",
                        "Verdict": "Block",
                        "Recommended_Action": "Remove the secret from the code and rotate or revoke the credential if it is valid.",
                    }
                )
        print(json.dumps(verdict, indent=2))


if __name__ == "__main__":
    if len(sys.argv) > 1:
        pr_url = sys.argv[1]
        result = check_secrets_in_pr(pr_url)
    else:
        print("Usage: python <script> <GitHub PR URL>")
