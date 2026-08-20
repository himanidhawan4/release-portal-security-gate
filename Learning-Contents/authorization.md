# GitHub API Authentication & Authorization

> 📚 Learning Documentation for **Release Portal Security Gate**
> 🎯 Covers GitHub Pull Requests, REST API, HTTP, PATs, Authentication, Authorization, Secret Management, Security Practices, Viva Questions, and Interview Preparation.

---

## 📑 Table of Contents

* [1. Project Context](#1-project-context)
* [2. Pull Requests](#2-pull-requests)
* [3. Pull Request URL](#3-pull-request-url)
* [4. API and REST API](#4-api-and-rest-api)
* [5. GitHub REST API Used in the Project](#5-github-rest-api-used-in-the-project)
* [6. HTTP Request and Response](#6-http-request-and-response)
* [7. JSON](#7-json)
* [8. Authentication vs Authorization](#8-authentication-vs-authorization)
* [9. Personal Access Token (PAT)](#9-personal-access-token-pat)
* [10. Fine-Grained PAT](#10-fine-grained-pat)
* [11. Fine-Grained PAT vs Classic PAT](#11-fine-grained-pat-vs-classic-pat)
* [12. Principle of Least Privilege](#12-principle-of-least-privilege)
* [13. Creating a Fine-Grained PAT](#13-creating-a-fine-grained-pat)
* [14. Environment Variables and `.env`](#14-environment-variables-and-env)
* [15. `.gitignore`](#15-gitignore)
* [16. `python-dotenv`](#16-python-dotenv)
* [17. HTTP Headers](#17-http-headers)
* [18. Authorization Header and Bearer Token](#18-authorization-header-and-bearer-token)
* [19. `Accept` Header](#19-accept-header)
* [20. Sending the GitHub API Request](#20-sending-the-github-api-request)
* [21. How GitHub Validates the Token](#21-how-github-validates-the-token)
* [22. Complete Authentication and Authorization Flow](#22-complete-authentication-and-authorization-flow)
* [23. HTTP Status Codes](#23-http-status-codes)
* [24. 401 vs 403](#24-401-vs-403)
* [25. PR Files, Patches, and Diffs](#25-pr-files-patches-and-diffs)
* [26. Diff Hunk Headers and Line Numbers](#26-diff-hunk-headers-and-line-numbers)
* [27. Why Scan Added Lines?](#27-why-scan-added-lines)
* [28. Security Architecture](#28-security-architecture)
* [29. Secret Management](#29-secret-management)
* [30. Why PATs Must Not Be Hardcoded](#30-why-pats-must-not-be-hardcoded)
* [31. Why PATs Must Not Be Printed](#31-why-pats-must-not-be-printed)
* [32. Token Expiration, Revocation, and Rotation](#32-token-expiration-revocation-and-rotation)
* [33. Credential Leakage](#33-credential-leakage)
* [34. What to Do If a PAT Is Leaked](#34-what-to-do-if-a-pat-is-leaked)
* [35. HTTPS](#35-https)
* [36. API Rate Limits](#36-api-rate-limits)
* [37. Error Handling](#37-error-handling)
* [38. Request Timeouts](#38-request-timeouts)
* [39. Defense in Depth](#39-defense-in-depth)
* [40. Production Considerations](#40-production-considerations)
* [41. Current Project Flow](#41-current-project-flow)
* [42. Authentication Implementation](#42-authentication-implementation)
* [43. Line-by-Line Explanation](#43-line-by-line-explanation)
* [44. Important Concept: `headers=headers`](#44-important-concept-headersheaders)
* [45. Important Concept: Authorization vs Accept](#45-important-concept-authorization-vs-accept)
* [46. Important Concept: PAT vs Authorization Header](#46-important-concept-pat-vs-authorization-header)
* [47. Common Viva Questions](#47-common-viva-questions)
* [48. Intermediate Interview Questions](#48-intermediate-interview-questions)
* [49. Advanced Interview Questions](#49-advanced-interview-questions)
* [50. Rapid Revision](#50-rapid-revision)
* [51. One-Line Interview Answer](#51-one-line-interview-answer)
* [52. Final Takeaways](#52-final-takeaways)
* [53. Security Reminder](#53-security-reminder)

---

# 1. Project Context

The **Release Portal Security Gate** is a Python-based security application that analyzes GitHub Pull Requests before changes are released.

The application retrieves Pull Request information through the GitHub REST API and analyzes the changed files and patches.

Current and planned security checks include:

* 🔐 Secret detection
* ☁️ IAM wildcard detection
* 🔎 Security policy checks
* 🚀 Future SAST/security checks

### High-Level Architecture

```text
Developer
    |
    | Creates Pull Request
    v
GitHub Repository
    |
    v
Release Portal Security Gate
    |
    | GitHub REST API
    v
PR Files + Patches
    |
    v
Security Analysis
    |
    +---- Secret Detection
    |
    +---- IAM Wildcard Detection
    |
    +---- Future Security Checks
    |
    v
Security Verdict
```

---

# 2. Pull Requests

A **Pull Request (PR)** is a request to review and potentially merge changes from one branch into another branch.

For example:

```text
feature/security-check
          |
          | Pull Request
          v
        main
```

A typical workflow is:

1. Create a feature branch.
2. Make code changes.
3. Push the branch to GitHub.
4. Create a Pull Request.
5. Review the changes.
6. Run automated checks.
7. Merge the Pull Request if the checks pass.

### Why is the Pull Request important in this project?

The security gate focuses on the changes introduced by the Pull Request.

```text
Pull Request
     |
     v
Changed Files
     |
     v
Patch / Diff
     |
     v
Security Analysis
```

---

# 3. Pull Request URL

A GitHub Pull Request URL generally follows this structure:

```text
https://github.com/<OWNER>/<REPOSITORY>/pull/<NUMBER>
```

Example:

```text
https://github.com/himanidhawan4/release-portal-security-gate-test/pull/1
```

The URL contains:

```text
Owner       = himanidhawan4
Repository  = release-portal-security-gate-test
Pull Number = 1
```

The Python application extracts these values so it can construct the appropriate GitHub API endpoint.

---

# 4. API and REST API

## What is an API?

API stands for:

> **Application Programming Interface**

An API provides a defined way for software applications to communicate with each other.

In this project:

```text
Python Application
       |
       | HTTP Request
       v
GitHub REST API
       |
       | HTTP Response
       v
Python Application
```

The Python application requests Pull Request information from GitHub.

## What is REST?

REST stands for:

> **Representational State Transfer**

REST is an architectural style commonly used to build web APIs.

Common HTTP methods include:

| Method   | Purpose                     |
| -------- | --------------------------- |
| `GET`    | Retrieve data               |
| `POST`   | Create data                 |
| `PUT`    | Replace/update a resource   |
| `PATCH`  | Partially update a resource |
| `DELETE` | Delete a resource           |

This project primarily uses `GET` because it retrieves Pull Request information.

---

# 5. GitHub REST API Used in the Project

The project uses the GitHub Pull Request files endpoint:

```text
GET /repos/{owner}/{repo}/pulls/{pull_number}/files
```

The API URL is constructed from the Pull Request information.

Example:

```text
https://api.github.com/repos/himanidhawan4/release-portal-security-gate-test/pulls/1/files
```

This endpoint provides information about files changed by the Pull Request.

The response can contain information such as:

* Filename
* File status
* Number of additions
* Number of deletions
* Patch/diff information

---

# 6. HTTP Request and Response

## HTTP Request

An HTTP request is a message sent from a client to a server.

In this project:

```text
Client = Python Application
Server = GitHub API
```

A request can contain:

* URL
* HTTP method
* Headers
* Query parameters
* Request body

For this project, the important parts are:

```text
Method  → GET
URL     → GitHub API endpoint
Headers → Authentication + response preferences
```

## HTTP Response

After receiving the request, GitHub sends an HTTP response.

A response generally contains:

* Status code
* Headers
* Response body

Example:

```text
HTTP/1.1 200 OK
```

The response body contains the requested API data.

---

# 7. JSON

JSON stands for:

> **JavaScript Object Notation**

JSON is a lightweight data-interchange format commonly used by REST APIs.

Example:

```json
{
  "filename": "testing.txt",
  "status": "added"
}
```

The Python `requests` library can parse a JSON response using:

```python
response.json()
```

---

# 8. Authentication vs Authorization

Authentication and authorization are related but different concepts.

## Authentication

Authentication answers:

> **Who are you?**

Examples include:

* Username and password
* Personal Access Token
* OAuth token
* API key
* SSH key
* Digital certificate

In this project, a GitHub PAT is used as the credential for authenticated API access.

## Authorization

Authorization answers:

> **What are you allowed to access or do?**

For example:

```text
Credential
    |
    v
Is it valid?
    |
    v
What identity/access is associated with it?
    |
    v
What repository/resource can it access?
    |
    v
What operation is permitted?
```

### Easy Way to Remember

```text
Authentication = Who are you?
Authorization  = What are you allowed to do?
```

Or:

```text
Authentication → Identity
Authorization  → Permissions / Access
```

---

# 9. Personal Access Token (PAT)

PAT stands for:

> **Personal Access Token**

A PAT is a credential that can be used for authenticated access to GitHub.

Instead of putting a GitHub password inside an application, a token designed for programmatic access can be used.

Conceptually:

```text
GitHub Account
      |
      v
Personal Access Token
      |
      +---- Repository Access
      |
      +---- Permissions
      |
      +---- Expiration
```

A PAT should be treated as a sensitive credential.

---

# 10. Fine-Grained PAT

GitHub provides **fine-grained Personal Access Tokens** that allow more specific control than the older classic PAT model.

Fine-grained tokens can provide control over:

* Selected repositories
* Repository permissions
* Token expiration
* Organization-related policies and restrictions

For this project, a fine-grained PAT is useful because the application should receive only the repository access and permissions it actually needs.

---

# 11. Fine-Grained PAT vs Classic PAT

| Feature                       | Fine-Grained PAT                   | Classic PAT                                            |
| ----------------------------- | ---------------------------------- | ------------------------------------------------------ |
| Repository control            | More granular                      | Broader                                                |
| Permission control            | More granular                      | Broader scope model                                    |
| Least privilege               | Easier to implement                | Generally less granular                                |
| Repository selection          | Can select specific repositories   | Typically broader access model                         |
| Security control              | More precise                       | Broader                                                |
| Recommended for new use cases | Generally preferred when supported | Mainly useful for compatibility/use cases requiring it |

The correct choice depends on the GitHub API operations required by the application.

For this project, the goal is to use the **smallest repository scope and minimum permissions required to read Pull Request data**.

---

# 12. Principle of Least Privilege

The **Principle of Least Privilege** means:

> Give a user, application, process, or credential only the minimum access required to perform its task.

### Excessive Access

```text
Token
 |
 +-- Read
 +-- Write
 +-- Delete
 +-- Administration
 +-- Everything else
```

### Least-Privilege Approach

```text
Token
 |
 v
Required Repository
 |
 v
Required Permission
```

If a token is compromised, smaller permissions and narrower repository access can reduce the potential impact.

---

# 13. Creating a Fine-Grained PAT

The general process is:

```text
GitHub Account
      |
      v
Settings
      |
      v
Developer Settings
      |
      v
Personal Access Tokens
      |
      v
Fine-Grained Tokens
      |
      +---- Set token name
      |
      +---- Set expiration
      |
      +---- Select repositories
      |
      +---- Select required permissions
      |
      v
Generate Token
```

> ⚠️ GitHub may display the token value only when it is created. Store it securely immediately.

For this project, select only the repository/repositories required by the security gate and only the permissions needed for the API operation.

---

# 14. Environment Variables and `.env`

An environment variable stores configuration outside the application's source code.

Example:

```text
GITHUB_TOKEN=your_token_here
```

The application can retrieve this value at runtime.

Benefits include:

* Keeps credentials outside source code
* Makes configuration easier
* Supports different environments
* Reduces accidental hardcoding

## `.env` for Local Development

A local `.env` file can contain:

```env
GITHUB_TOKEN=your_actual_token_here
```

The actual token must never be committed to the repository.

> ⚠️ `.env` is a local configuration mechanism, not a complete secret-management solution.

---

# 15. `.gitignore`

The `.env` file should be added to `.gitignore`:

```gitignore
.env
```

This helps prevent Git from tracking the file.

However:

> `.gitignore` is **not a secret manager**.

It does not encrypt the file and does not protect a secret that has already been committed.

---

# 16. `python-dotenv`

The project uses the `python-dotenv` package.

Install it using:

```bash
pip install python-dotenv
```

Import it:

```python
from dotenv import load_dotenv
```

Then load the environment variables:

```python
load_dotenv()
```

The flow is:

```text
.env
 |
 v
load_dotenv()
 |
 v
Environment Variables
```

---

# 17. HTTP Headers

HTTP headers provide additional information about an HTTP request or response.

Examples include:

```text
Authorization
Accept
Content-Type
User-Agent
```

The project creates headers similar to:

```python
headers = {
    "Authorization": f"Bearer {github_token}",
    "Accept": "application/vnd.github+json",
}
```

These headers have different purposes.

---

# 18. Authorization Header and Bearer Token

The `Authorization` header carries authentication credentials according to the selected authentication scheme.

Example:

```text
Authorization: Bearer <TOKEN>
```

In Python:

```python
"Authorization": f"Bearer {github_token}"
```

The flow is:

```text
Python Application
       |
       v
Create Authorization Header
       |
       v
Send HTTP Request
       |
       v
GitHub
       |
       v
GitHub validates the credential
```

### Important

The Python `headers` dictionary does **not** itself perform authorization.

It only places the required authentication information into the outgoing HTTP request.

GitHub performs the actual credential validation and access checks.

---

# 19. `Accept` Header

The project also uses:

```python
"Accept": "application/vnd.github+json"
```

The `Accept` header tells the server which response media types the client prefers.

Therefore:

```text
Authorization
    ↓
Authentication credentials

Accept
    ↓
Preferred response representation
```

So:

> `Accept` is **not** an authentication mechanism.

---

# 20. Sending the GitHub API Request

The request is sent using Python's `requests` library.

Example:

```python
response = requests.get(
    requestapi,
    headers=headers,
    timeout=10
)
```

This means:

```text
requests.get()
 |
 +-- requestapi
 |      |
 |      +-- Destination URL
 |
 +-- headers
 |      |
 |      +-- Authentication + response preferences
 |
 +-- timeout
        |
        +-- Maximum waiting time
```

The `timeout` prevents the application from waiting indefinitely for a network response.

---

# 21. How GitHub Validates the Token

The PAT was generated by GitHub.

When the application sends:

```text
Authorization: Bearer <PAT>
```

GitHub can validate the credential and apply the access associated with that token.

Conceptually:

```text
Python Application
       |
       | Authorization: Bearer PAT
       v
GitHub API
       |
       +-- Is the credential valid?
       |
       +-- Is it expired/revoked?
       |
       +-- Which repositories are accessible?
       |
       +-- Which permissions are available?
       |
       v
Request Allowed / Refused
```

The application does not decide whether the PAT is valid.

GitHub makes that decision.

---

# 22. Complete Authentication and Authorization Flow

```text
Create Fine-Grained PAT
        |
        v
Store PAT Securely
        |
        v
.env
        |
        v
load_dotenv()
        |
        v
os.getenv("GITHUB_TOKEN")
        |
        v
github_token
        |
        v
Authorization Header
        |
        v
requests.get()
        |
        v
HTTPS Request
        |
        v
GitHub API
        |
        v
Credential Validation
        |
        v
Access / Permission Checks
        |
        +------------------+
        |                  |
        v                  v
     Allowed             Refused
        |                  |
        v                  v
  API Response          401/403/etc.
        |
        v
PR Files + Patches
        |
        v
Security Analysis
```

---

# 23. HTTP Status Codes

HTTP status codes communicate the result of an HTTP request.

Important examples:

| Status Code | General Meaning                                                          |
| ----------- | ------------------------------------------------------------------------ |
| `200`       | Success                                                                  |
| `400`       | Bad Request                                                              |
| `401`       | Authentication credentials are missing/invalid or otherwise not accepted |
| `403`       | Request is forbidden/refused                                             |
| `404`       | Resource not found                                                       |
| `429`       | Too Many Requests                                                        |
| `500`       | Internal Server Error                                                    |

The exact meaning and cause should be determined from the API documentation and response body.

---

# 24. 401 vs 403

This is a common interview question.

## 401 Unauthorized

A `401` generally indicates an authentication problem.

Possible causes include:

* Missing credentials
* Invalid credentials
* Expired credentials
* Revoked credentials

## 403 Forbidden

A `403` means the server is refusing the request.

Possible causes can include:

* Insufficient permissions
* Repository restrictions
* Organization policies
* Rate limiting
* Other GitHub security restrictions

### Easy Way to Remember

```text
401 → Authentication problem
403 → Request forbidden/refused
```

> ⚠️ Do not assume that every `403` means insufficient permissions. The response body and headers should also be inspected.

---

# 25. PR Files, Patches, and Diffs

The Pull Request files endpoint provides information about changed files.

The project extracts values such as:

```python
filename = i.get("filename")
patch = i.get("patch")
```

The application can then store:

```python
details.append((filename, patch))
```

Conceptually:

```text
Pull Request
     |
     v
Changed Files
     |
     +---- Filename
     |
     +---- Patch
              |
              v
       Security Analysis
```

---

# 26. Diff Hunk Headers and Line Numbers

A patch can contain a hunk header such as:

```text
@@ -25,3 +40,5 @@
```

Conceptually:

```text
-25,3
```

refers to the relevant section of the old file.

```text
+40,5
```

refers to the relevant section of the new file.

The security gate uses the new-file line information to associate security findings with the correct line numbers.

---

# 27. Why Scan Added Lines?

The security gate focuses on newly introduced changes.

For example:

```diff
@@ -10,2 +10,4 @@
 existing line
+new line
+another new line
```

The added lines are the lines beginning with `+`.

Scanning added lines provides several benefits:

* Focuses on newly introduced code
* Reduces unnecessary scanning
* Makes findings easier to associate with the Pull Request
* Helps identify vulnerabilities introduced by the change

Conceptually:

```text
Existing Code
     |
     v
Already Present

New PR Changes
     |
     v
Security Scan
```

---

# 28. Security Architecture

The project architecture can be represented as:

```text
Developer
    |
    | Creates Pull Request
    v
GitHub Repository
    |
    v
Release Portal Security Gate
    |
    v
GitHub REST API
    |
    | PAT Authentication
    v
PR Files + Patches
    |
    v
Security Analysis
    |
    +---- Secret Detection
    |
    +---- IAM Wildcard Detection
    |
    +---- Future Security Checks
    |
    v
Security Verdict
```

---

# 29. Secret Management

Secrets include sensitive credentials such as:

* PATs
* API keys
* Passwords
* Private keys
* Cloud credentials
* Database passwords

For local development:

```text
.env
```

can be used.

For production environments, a dedicated secret-management mechanism is preferable, such as:

```text
Secret Manager
CI/CD Secret Store
Platform Secret Store
```

The general principle is:

```text
Secret
  |
  v
Secure Storage
  |
  v
Application
```

---

# 30. Why PATs Must Not Be Hardcoded

Never do this:

```python
github_token = "actual_secret_token"
```

Problems include:

* The secret becomes part of the source code.
* It can enter Git history.
* Code reviewers may see it.
* It can accidentally be published.
* Rotation becomes difficult.
* Other developers may gain access to the credential.

Better:

```python
github_token = os.getenv("GITHUB_TOKEN")
```

---

# 31. Why PATs Must Not Be Printed

Never do this:

```python
print(github_token)
```

Logs and terminal output may be:

* Saved
* Shared
* Uploaded
* Included in CI/CD logs
* Captured in screenshots

Instead:

```python
if github_token:
    print("GitHub token loaded successfully")
else:
    print("GitHub token NOT loaded")
```

This confirms whether the value was loaded without revealing the credential.

---

# 32. Token Expiration, Revocation, and Rotation

## Token Expiration

Expiration limits how long a token remains usable.

```text
Token Created
      |
      v
Token Valid
      |
      v
Expiration
      |
      v
Token No Longer Valid
```

## Token Revocation

Revocation invalidates a token before or independently of its expiration.

```text
PAT Compromised
      |
      v
Revoke PAT
      |
      v
Future Requests Using That PAT Fail
```

## Token Rotation

Rotation replaces an existing credential with a new credential.

```text
Old PAT
   |
   v
Create New PAT
   |
   v
Update Application
   |
   v
Test
   |
   v
Revoke Old PAT
```

---

# 33. Credential Leakage

A PAT can accidentally leak through:

* Source code
* Git history
* `.env` files
* Logs
* CI/CD output
* Screenshots
* Documentation
* Public repositories
* Chat messages
* Error messages

Therefore:

```text
Secret
  |
  +-- Do not commit
  |
  +-- Do not print
  |
  +-- Do not share
  |
  +-- Store securely
  |
  +-- Rotate when required
```

---

# 34. What to Do If a PAT Is Leaked

If a PAT is accidentally exposed:

1. Treat it as compromised.
2. Revoke the token immediately.
3. Create a replacement if required.
4. Update the application.
5. Investigate where it was exposed.
6. Remove the secret from inappropriate locations.
7. Check Git history if it was committed.
8. Review relevant logs and systems.
9. Verify repository and account security.

> ⚠️ Deleting a secret from the latest version of a file does not necessarily remove it from Git history.

---

# 35. HTTPS

The GitHub API uses HTTPS:

```text
https://api.github.com
```

HTTPS protects data in transit by encrypting the communication channel between the client and server.

Conceptually:

```text
Python Application
       |
       | Encrypted HTTPS Connection
       v
GitHub API
```

This is especially important because the request contains sensitive authentication information.

---

# 36. API Rate Limits

GitHub APIs can enforce rate limits.

If an application makes too many requests, GitHub may restrict or reject requests.

A production implementation should consider:

* Rate-limit handling
* Retry logic
* Exponential backoff
* Avoiding unnecessary API calls
* Appropriate caching where useful

A `403` can occur in some rate-limit situations, so the application should inspect the response details instead of assuming every `403` is a permission problem.

---

# 37. Error Handling

The application should handle expected API failures.

For example:

```python
if response.status_code == 401:
    print("Error 401: GitHub authentication failed.")
    return []
```

And:

```python
if response.status_code == 403:
    print("Error 403: GitHub refused the request.")
    return []
```

A production implementation should additionally consider:

* Network errors
* Connection errors
* Timeouts
* Rate limits
* Retryable failures
* Invalid JSON
* Unexpected API responses
* Server errors

Using `response.raise_for_status()` can also be useful when the application wants `requests` to raise an exception for HTTP error responses.

---

# 38. Request Timeouts

HTTP requests should generally use a timeout.

Example:

```python
response = requests.get(
    requestapi,
    headers=headers,
    timeout=10
)
```

Without an appropriate timeout, a network operation can potentially wait for an excessively long time.

The timeout helps keep the application responsive and prevents indefinite waiting.

---

# 39. Defense in Depth

**Defense in Depth** means using multiple security controls instead of relying on a single control.

For this project:

```text
Fine-Grained PAT
       +
Least Privilege
       +
.env Protection
       +
.gitignore
       +
No Secret Logging
       +
HTTPS
       +
Token Expiration
       +
Token Rotation
       +
Error Handling
       +
Monitoring
```

If one security layer fails, other controls can still reduce the impact.

---

# 40. Production Considerations

The current implementation is suitable for learning and project development.

A production-grade implementation could additionally use:

* Dedicated secret management
* CI/CD secret stores
* Request timeouts
* Retry and backoff
* Rate-limit handling
* Structured logging
* Secret masking
* Monitoring
* Audit logging
* Token rotation
* Strong input validation
* Pull Request URL validation
* Minimal permissions
* Automated security checks

The overall goal is:

```text
Secure Credential
       +
Secure Communication
       +
Least Privilege
       +
Reliable Error Handling
       +
Monitoring
```

---

# 41. Current Project Flow

The complete project flow is:

```text
                    GitHub Pull Request
                            |
                            v
                     Pull Request URL
                            |
                            v
                     Python Application
                            |
                            v
                 Parse Owner / Repo / PR
                            |
                            v
                        Load .env
                            |
                            v
                   Read GITHUB_TOKEN
                            |
                            v
                Create Authorization Header
                            |
                            v
                    HTTPS GET Request
                            |
                            v
                       GitHub API
                            |
                            v
                 Authentication / Access
                            |
                    +-------+-------+
                    |               |
                 Allowed          Refused
                    |               |
                    v               v
              PR File Data       401 / 403
                    |
                    v
              Extract Patches
                    |
                    v
              Security Analysis
                    |
             +------+------+
             |             |
             v             v
      Secret Detection   IAM Checks
             |             |
             +------+------+
                    |
                    v
              Security Verdict
```

---

# 42. Authentication Implementation

A simplified authentication implementation is:

```python
import os
import requests
from dotenv import load_dotenv

load_dotenv()

github_token = os.getenv("GITHUB_TOKEN")

if github_token:
    print("GitHub token loaded successfully")
else:
    print("GitHub token NOT loaded")

headers = {
    "Authorization": f"Bearer {github_token}",
    "Accept": "application/vnd.github+json",
}

response = requests.get(
    requestapi,
    headers=headers,
    timeout=10
)
```

The actual project may place this logic inside the GitHub client module.

---

# 43. Line-by-Line Explanation

## Import `os`

```python
import os
```

The `os` module provides access to environment variables.

---

## Import `requests`

```python
import requests
```

The `requests` library is used to send HTTP requests.

---

## Import `load_dotenv`

```python
from dotenv import load_dotenv
```

Imports the function that loads variables from `.env`.

---

## Load `.env`

```python
load_dotenv()
```

Loads variables from the `.env` file into the environment.

---

## Retrieve the PAT

```python
github_token = os.getenv("GITHUB_TOKEN")
```

Retrieves the value associated with the `GITHUB_TOKEN` environment variable.

---

## Check Whether the Token Exists

```python
if github_token:
    print("GitHub token loaded successfully")
else:
    print("GitHub token NOT loaded")
```

This checks whether a value was retrieved.

It does **not** reveal the token itself.

---

## Create HTTP Headers

```python
headers = {
    "Authorization": f"Bearer {github_token}",
    "Accept": "application/vnd.github+json",
}
```

Creates the headers that will be sent with the API request.

The `Authorization` header contains the credential.

The `Accept` header specifies the preferred response format.

---

## Send the Request

```python
response = requests.get(
    requestapi,
    headers=headers,
    timeout=10
)
```

Sends a GET request to GitHub with the specified headers and timeout.

---

# 44. Important Concept: `headers=headers`

This is a common beginner confusion.

Consider:

```python
requests.get(
    requestapi,
    headers=headers
)
```

The first `headers` is the parameter expected by `requests.get()`.

The second `headers` is the Python variable containing the dictionary.

Conceptually:

```text
requests.get(
    headers = Python variable
)
```

The Python dictionary might contain:

```python
{
    "Authorization": "Bearer <PAT>",
    "Accept": "application/vnd.github+json"
}
```

Therefore:

> `headers=headers` does not itself perform authorization. It passes the HTTP headers to the request.

GitHub performs the actual authentication and authorization checks.

---

# 45. Important Concept: Authorization vs Accept

These headers have different responsibilities:

```python
headers = {
    "Authorization": f"Bearer {github_token}",
    "Accept": "application/vnd.github+json",
}
```

## Authorization

```text
Authorization
      |
      v
Authentication credential
```

## Accept

```text
Accept
      |
      v
Preferred response representation
```

Therefore:

```text
Authorization != Accept
```

---

# 46. Important Concept: PAT vs Authorization Header

The PAT itself is the credential:

```python
github_token
```

The authorization header places that credential into the HTTP request:

```python
"Authorization": f"Bearer {github_token}"
```

Then `requests.get()` sends the request.

Therefore:

```text
PAT
 |
 v
github_token
 |
 v
Authorization Header
 |
 v
HTTP Request
 |
 v
GitHub
 |
 v
Authentication + Access Checks
```

---

# 47. Common Viva Questions

## Q1. What is an API?

An API is an interface that allows different software applications to communicate with each other.

## Q2. What is REST?

REST stands for Representational State Transfer and is an architectural style commonly used for web APIs.

## Q3. What is a Pull Request?

A Pull Request is a request to review and potentially merge changes from one branch into another.

## Q4. What HTTP method does your application use?

The application primarily uses `GET` because it retrieves Pull Request file information.

## Q5. What is JSON?

JSON is a lightweight data-interchange format commonly used by APIs.

## Q6. What is authentication?

Authentication verifies the identity or credential of a requester.

## Q7. What is authorization?

Authorization determines what an authenticated requester is allowed to access or perform.

## Q8. What is a PAT?

A Personal Access Token is a credential used for authenticated programmatic access to GitHub.

## Q9. Why use a PAT?

The application needs authenticated access to GitHub's API without placing a GitHub password inside the application.

## Q10. What is a fine-grained PAT?

It is a PAT that provides more granular control over repositories and permissions.

## Q11. Why use a fine-grained PAT?

It supports narrower access and makes least-privilege configuration easier.

---

# 48. Intermediate Interview Questions

## Q12. Why use `.env`?

For local development, `.env` provides a convenient way to keep configuration and credentials outside source code.

## Q13. What does `load_dotenv()` do?

It loads variables from `.env` into the process environment.

## Q14. What does `os.getenv()` do?

It retrieves an environment variable's value.

## Q15. Why add `.env` to `.gitignore`?

To help prevent accidental tracking and committing of the file.

## Q16. Is `.gitignore` enough to protect a PAT?

No. It does not encrypt the file and cannot remove a secret that has already been committed.

## Q17. Why should a PAT not be hardcoded?

Because it could become part of the source code or Git history and may be exposed.

## Q18. Why should a PAT not be printed?

Because terminal output, application logs, or CI/CD logs can expose the credential.

## Q19. What is least privilege?

Giving only the minimum access required for a task.

## Q20. What is token rotation?

Replacing an existing credential with a new credential.

## Q21. What is token revocation?

Invalidating a credential so it can no longer be used.

## Q22. Can multiple PATs be used?

Yes. Different requests can use different credentials, but this increases secret-management complexity.

## Q23. Can the variable `headers` be renamed?

Yes.

For example:

```python
request_headers = {
    "Authorization": f"Bearer {github_token}"
}

requests.get(
    requestapi,
    headers=request_headers
)
```

The variable name is chosen by the developer.

---

# 49. Advanced Interview Questions

## Q24. Does the Python `headers` dictionary perform authorization?

No.

It only contains HTTP headers that are sent to GitHub.

GitHub performs the actual credential validation and access checks.

## Q25. How does GitHub know whether the PAT is valid?

The PAT is generated by GitHub. When the application presents it in the appropriate authentication header, GitHub can validate the credential and apply the access associated with it.

## Q26. Is authentication enough to access a private repository?

No.

The credential must also have the appropriate repository access and permissions.

## Q27. Why might a valid token receive a 403?

Possible reasons include:

* Insufficient permissions
* Repository access restrictions
* Organization policies
* Rate limiting
* Other GitHub restrictions

## Q28. Why is HTTPS important when sending a PAT?

HTTPS encrypts the communication channel and helps protect the credential while it is transmitted.

## Q29. Is HTTPS enough to protect a PAT?

No.

HTTPS does not protect against:

* Hardcoded secrets
* Secret logging
* Git commits
* Screenshots
* Malware
* Excessive permissions
* Exposed local files

## Q30. What is defense in depth?

Using multiple independent security controls instead of relying on one mechanism.

## Q31. How would you improve this authentication system for production?

Possible improvements include:

* Use a dedicated secret manager.
* Add request timeouts.
* Handle network exceptions.
* Handle rate limits.
* Implement appropriate retry/backoff.
* Use least-privilege permissions.
* Rotate credentials.
* Avoid sensitive logging.
* Add monitoring and audit logging.
* Validate Pull Request URLs.
* Validate API responses.

---

# 50. Rapid Revision

Remember these concepts:

```text
API
→ Allows software systems to communicate.

REST API
→ Architectural style commonly used for web APIs.

GET
→ Retrieves data.

Pull Request
→ Request to review and potentially merge changes.

PAT
→ Personal Access Token.

Authentication
→ Who are you?

Authorization
→ What are you allowed to access or do?

Fine-Grained PAT
→ More granular repository and permission control.

Least Privilege
→ Minimum required access.

Authorization Header
→ Carries authentication credentials.

Bearer
→ Authentication scheme used with the token.

Accept Header
→ Preferred response representation.

.env
→ Local environment configuration.

load_dotenv()
→ Loads .env variables.

os.getenv()
→ Reads an environment variable.

200
→ Successful response.

401
→ Authentication problem.

403
→ Request forbidden/refused.

HTTPS
→ Protects communication in transit.

Token Rotation
→ Replace an existing credential.

Token Revocation
→ Invalidate a credential.

Defense in Depth
→ Multiple layers of security.
```

---

# 51. One-Line Interview Answer

If the interviewer asks:

> **"Explain how your application securely accesses GitHub Pull Requests."**

A strong answer is:

> My Python security gate uses the GitHub REST API to retrieve Pull Request files and patches. I use a fine-grained Personal Access Token stored outside the source code as an environment variable. The token is loaded using `python-dotenv` and sent through the HTTP `Authorization: Bearer` header over HTTPS. GitHub validates the credential and applies its repository and permission restrictions. The application handles successful and error responses while following security principles such as least privilege, avoiding secret logging, and excluding `.env` from Git.

---

# 52. Final Takeaways

The most important concepts from this implementation are:

1. A Pull Request contains changes that can be analyzed for security issues.
2. The GitHub REST API allows applications to retrieve Pull Request data.
3. A PAT is a credential used for programmatic GitHub access.
4. Authentication verifies a credential.
5. Authorization determines what access that credential has.
6. Fine-grained PATs provide more granular access control.
7. Environment variables keep credentials outside source code.
8. `.env` is useful for local development but is not itself a secret manager.
9. `.gitignore` helps prevent accidental commits but does not encrypt secrets.
10. The `Authorization` header carries the authentication credential.
11. The `Accept` header specifies the preferred response representation.
12. `headers=headers` passes the Python dictionary to `requests.get()`.
13. HTTP `401` generally indicates an authentication problem.
14. HTTP `403` indicates that the request is being refused and can have multiple causes.
15. HTTPS protects credentials while they are transmitted.
16. Least privilege reduces the potential impact of credential compromise.
17. PATs should never be printed, hardcoded, or committed.
18. Leaked credentials should be revoked immediately.
19. Token expiration and rotation are important security practices.
20. Production systems should use appropriate secret-management and security controls.

---

# 53. Security Reminder

> ⚠️ **NEVER put your real PAT inside this documentation.**

Use placeholders such as:

```text
<YOUR_GITHUB_PAT>
```

or:

```text
your_token_here
```

Never include an actual working credential in:

* `Authorization.md`
* `README.md`
* Source code
* Git commits
* Screenshots
* Chat messages
* Public repositories
* Documentation

If a real PAT is ever exposed, treat it as compromised and revoke it immediately.

---

## 📌 Project Learning Goal

This documentation demonstrates understanding of:

* GitHub Pull Requests
* GitHub REST API
* HTTP
* REST
* JSON
* Authentication
* Authorization
* Personal Access Tokens
* Fine-Grained PATs
* Environment Variables
* `.env`
* `.gitignore`
* HTTP Headers
* Bearer Authentication
* HTTP Status Codes
* HTTPS
* Secret Management
* Least Privilege
* Defense in Depth
* Credential Rotation
* Credential Revocation
* DevSecOps Security Practices
