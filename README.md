# 🔐 Risk-Aware DevSecOps Release Gate

**Automated DevSecOps Change Risk Assessment and Remediation Platform for GitHub Pull Requests**

A Python-based security gate that takes a GitHub Pull Request URL, retrieves the PR and its changed files through the GitHub API, runs four security checks (secrets, IAM wildcards, vulnerable dependencies, SonarCloud analysis), converts the findings into a numerical **risk score**, and produces a final **ALLOW / BLOCK** verdict with reasons and recommendations.

> **Detect → Score → Explain → Recommend → Decide**

---

## 📑 Table of Contents

1. [Features](#-features)
2. [Advantages](#-advantages)
3. [How It Works](#-how-it-works)
4. [System Architecture](#️-system-architecture)
5. [Security Checks in Detail](#-security-checks-in-detail)
6. [Risk Scoring](#-risk-scoring)
7. [Release Decision (ALLOW / BLOCK)](#-release-decision-allow--block)
8. [Report Structure](#-report-structure)
9. [Web Interface](#-web-interface)
10. [Project Structure](#-project-structure)
11. [Prerequisites](#️-prerequisites)
12. [Installation](#-installation)
13. [Configuration (.env)](#-configuration-env)
14. [Usage](#️-usage)
15. [Helper Files](#-helper-files)
16. [Security & Privacy](#-security--privacy)
17. [Technology Stack](#️-technology-stack)
18. [Limitations](#-limitations)
19. [Future Scope](#-future-scope)
20. [Author](#-author)

---

## 🚀 Features

* 🔗 Analyze a GitHub Pull Request using only its URL
* 🐙 Retrieve PR information (title, state, commits, additions, deletions, branches, head commit SHA, clone URL) and changed-file patches through the GitHub REST API
* 🔑 Detect exposed secrets with **detect-secrets** (25 detector plugins)
* ☁️ Detect IAM wildcard permissions (`Action: "*"`, `Resource: "*"`) in `.tf` and `.json` files
* 📦 Scan dependency changes for known vulnerabilities with the **OSV.dev** API (PyPI and npm)
* 🔎 Run **SonarCloud** analysis on the PR commit and read its Quality Gate and issues
* 📊 Calculate a risk score (maximum 100) with a per-category breakdown and a calculation table
* 🚦 Generate a final **ALLOW / BLOCK** verdict based on mandatory block conditions
* 💡 Provide reasons and, when requested, recommendations for each finding
* 🌐 Flask-based web interface for submitting Pull Requests
* 🖥️ CLI support for running the security gate
* 🔐 Credentials supplied through environment variables (`.env`)
* 🛡️ Does not store user information as part of the assessment workflow

---

## ✅ Advantages

* **Combined assessment:** secrets, IAM, dependency and SonarCloud results are evaluated together and reduced to a single ALLOW / BLOCK verdict.
* **Based on the PR's changes:** the secret, IAM and dependency checks scan only the lines added by the Pull Request, and reported line numbers are calculated from the diff.
* **Explained findings:** every finding carries a reason, and with details enabled also a recommendation (for example rotate a secret, narrow an IAM scope, or upgrade a package to a specific fixed version).
* **Transparent risk score:** the report shows category scores, how each finding contributed (base points × multiplier), the methodology, the risk thresholds and the mandatory block conditions.
* **Dependency findings are verified:** a vulnerability is reported only when the exact dependency version falls inside the affected range, and equivalent advisories (GHSA / PYSEC / aliases) are de-duplicated.
* **Reduced score inflation:** diminishing multipliers make repeated findings in one category add progressively less to the score.
* **Current SonarCloud explanations:** rule names, reasons and recommendations are fetched from the SonarCloud API at scan time instead of being hard-coded.
* **Exact-commit analysis:** SonarCloud analyzes the PR's head commit SHA.
* **Errors block the release:** an exception or missing result from a scanner is recorded as `ERROR`, and any scanner error forces a `BLOCK` verdict.
* **No source code in the report:** findings contain file name, line number, issue type and guidance, not source lines or secret values.
* **Dynamic PR handling:** owner, repository, PR number, branches and commit SHA are extracted from the URL and GitHub API, not hard-coded.
* **Two ways to run:** web interface and CLI.
* **Temporary clone is always removed:** the repository cloned for SonarCloud is deleted after every scan, including failures and Ctrl+C.
* **Credentials stay out of the source:** tokens are read from `.env`, which is listed in `.gitignore`.

---

## 🔄 How It Works

```text
Enter GitHub PR URL
        ↓
Validate URL (web interface) / read argument (CLI)
        ↓
Fetch PR information + changed files (GitHub API)
        ↓
Run the four scanners (each in its own error handler)
   ├── Secrets       → added lines
   ├── IAM           → added lines of .tf / .json files
   ├── Dependencies  → added lines of dependency files → OSV.dev
   └── SonarCloud    → clone repo, checkout PR head SHA, run SonarScanner
        ↓
Normalize all findings into one common structure
        ↓
Calculate risk score
        ↓
Calculate final verdict (ALLOW / BLOCK)
        ↓
Build report → web interface / CLI JSON
```

---

## 🏗️ System Architecture

```text
                    GitHub Pull Request URL
                              │
                              ▼
                    ┌───────────────────┐
                    │   GitHub Client   │   src/github_client.py
                    │  PR + File Data   │
                    └─────────┬─────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │  Security Gate      │   src/main.py → run_security_gate()
                   └──────────┬──────────┘
                              │
     ┌──────────────┬─────────┴────────┬──────────────┐
     ▼              ▼                  ▼              ▼
┌──────────┐  ┌───────────┐   ┌──────────────┐  ┌────────────┐
│ Secrets  │  │    IAM    │   │ Dependency   │  │ SonarCloud │
│ detect-  │  │ Wildcard  │   │ OSV.dev Scan │  │   Scan     │
│ secrets  │  │  Checks   │   │              │  │            │
└────┬─────┘  └─────┬─────┘   └──────┬───────┘  └─────┬──────┘
     └──────────────┴────────┬───────┴────────────────┘
                             ▼
                  ┌─────────────────────┐
                  │  Risk Scoring       │
                  └──────────┬──────────┘
                             ▼
                  ┌─────────────────────┐
                  │  Final Verdict      │
                  │  ALLOW / BLOCK      │
                  └──────────┬──────────┘
                             ▼
                 Flask Web Interface / CLI
```

---

## 🔍 Security Checks in Detail

### 0. 🐙 GitHub Client (`src/github_client.py`)

`fetch_pr_details(pr_url)` supplies the data used by all scanners.

* Parses owner, repository and PR number from the URL (`https://github.com/OWNER/REPOSITORY/pull/NUMBER`).
* Authenticates with `GITHUB_TOKEN` (loaded from `.env`) using a Bearer token.
* Calls the GitHub API for the Pull Request and for its changed files.
* Returns: owner, repo, pull number, title, state, commit count, changed-file count, additions, deletions, head branch, base branch, head SHA, clone URL (the PR head repository, falling back to the base repository) and the list of `(filename, patch)` pairs.
* Prints clear errors and returns `None` for: invalid PR URL, missing `GITHUB_TOKEN`, connection failure, HTTP 401 (invalid/expired token), 403 (insufficient permission), 404 (PR or repository not found), other non-200 responses, and missing branch / SHA / clone URL data.

### 1. 🔑 Secret Detection (`src/checks/secrets.py`)

Uses `detect-secrets` (`transient_settings` + `scan.scan_line`) on every added line of every changed file. Line numbers are computed from the `@@` hunk headers.

**Detector plugins (25):** Artifactory · AWS Key · Azure Storage Key · Basic Auth · Cloudant · Discord Bot Token · GitHub Token · GitLab Token · IBM Cloud IAM · IBM COS HMAC · Public IP Address · JWT · Keyword (Secret Keyword) · Mailchimp · NPM · OpenAI · Private Key · PyPI Token · SendGrid · Slack · SoftLayer · Square OAuth · Stripe · Telegram Bot Token · Twilio Key

**Behavior**

* Every finding has severity `CRITICAL` and verdict `BLOCK`.
* Each secret type has its own explanation of the risk; unknown types get a generic "may expose sensitive information" reason.
* With details enabled the recommendation is: remove the secret from the code, rotate or revoke the credential if valid, and use a secure secret-management mechanism or protected environment variable.
* A finding contains file, line and issue (type) only. The secret value is not returned.

### 2. ☁️ IAM Wildcard Check (`src/checks/iam.py`)

Scans added lines of `.tf` and `.json` files. The patterns handle indentation, quoted or unquoted keys, `=` and `:` separators, and single-element list syntax (`["*"]`). Comment lines (`#`, `//`) are skipped.

| Finding | Severity | Meaning |
| --- | --- | --- |
| `Action` = `*` | **CRITICAL** | Grants all AWS API operations; violates least privilege and increases blast radius |
| `Resource` = `*` | **HIGH** | Applies permissions to all resources; some AWS actions legitimately require `*`, so it must be judged per service/action |

* Every finding has verdict `BLOCK`, a detailed reason and (with details enabled) a recommendation: use specific actions, narrow resource ARNs, add `Condition` keys, use IAM Access Analyzer and CloudTrail review, separate permissions by workload, and apply permission boundaries or organization-level controls.
* Findings are sorted by severity. The scanner verdict is `FAIL` if any `CRITICAL` or `HIGH` finding exists, otherwise `PASS`.

### 3. 📦 Dependency Vulnerability Scan (`src/checks/cve.py`)

Queries `https://api.osv.dev/v1/query` (15-second timeout) for each added dependency.

| File | Ecosystem | What is scanned |
| --- | --- | --- |
| Any `*.txt` (e.g. `requirements.txt`) | PyPI | Exact pins (`package==version`) only |
| `package.json` | npm | `"name": "version"` entries (`~`, `^`, `<`, `>`, `=` prefixes removed) |
| `package-lock.json` | npm | `"name": "version"` entries |

**Processing**

1. Extract added lines and their line numbers from the patch.
2. Parse `(package, version)`; each unique package/version/ecosystem is queried once.
3. De-duplicate equivalent OSV advisories using IDs and aliases (GHSA records and records with known severity are preferred).
4. Confirm that the installed version is affected using OSV `versions` lists and `introduced` / `fixed` / `last_affected` ranges.
5. Determine severity in this order: `database_specific.severity` → numeric CVSS score (≥ 9.0 Critical, ≥ 7.0 High, ≥ 4.0 Medium, > 0 Low; v3 and v4) → direct severity value → `UNKNOWN`.
6. Build the recommendation: upgrade to the smallest fixed version newer than the installed one, or to the latest secure release when no fixed version is known.
7. Final de-duplication by package, version and advisory ID.

**Finding verdict:** `CRITICAL`, `HIGH`, `MEDIUM`, `MODERATE` → `BLOCK`; `LOW`, `UNKNOWN` → `WARN`.
**Scanner verdict:** `FAIL` if any finding exists, otherwise `PASS`.
**Result fields:** `total_dependencies`, `vulnerable_dependencies` (unique packages), `total_vulnerabilities`, `findings`.

### 4. 🔎 SonarCloud Analysis (`src/checks/sonarqube.py`)

```text
Fetch PR details → Clone repository (temporary directory) → Checkout PR head SHA
   → Run SonarScanner with PR parameters → Find ceTaskId
   → Wait for analysis to finish → Fetch Quality Gate → Fetch issues
   → Fetch rule details → Build findings → Delete temporary clone
```

* Required `.env` values: `SONAR_TOKEN`, `SONAR_ORGANIZATION`, `SONAR_PROJECT_KEY`. SonarScanner is found through `SONAR_SCANNER_PATH`, then `sonar-scanner`, then `sonar-scanner.bat` on `PATH`.
* The scanner is run with the PR number, source branch and target branch (`sonar.pullrequest.key`, `.branch`, `.base`).
* The task ID is read from `.scannerwork/report-task.txt`, with fallbacks to the scanner output. The task is polled every 5 seconds for up to 300 seconds.
* Quality Gate: `/api/qualitygates/project_status`. Issues: `/api/issues/search` (unresolved issues of the PR, up to 500).
* Rule name, reason and recommendation are fetched dynamically from `/api/rules/show`; the HTML is cleaned into readable text. No rule IDs are hard-coded.
* Each finding contains filename, line, issue message, severity, type and rule name; reason and recommendation are added when details are enabled.
* Result: `tool`, `status`, `quality_gate`, `total_issues`, `findings`, `project_key`. A readable summary (or detailed report) and the final JSON are also printed to the console.
* The temporary clone is deleted in a `finally` block; on Windows deletion is retried and read-only files are handled.
* Returns `None` (recorded by the gate as an `ERROR`) on missing configuration, scanner not found, PR fetch failure, clone or checkout failure, scanner failure, missing task ID, analysis failure/timeout, or Quality Gate / issue retrieval failure.

---

## 📊 Risk Scoring

Implemented in `calculate_risk_score()` (`src/main.py`).

**Base points**

| Severity | Points |
| --- | ---: |
| Blocker / Critical | 10 |
| High | 7 |
| Medium / Moderate / Major | 4 |
| Low / Minor | 2 |

**Diminishing multipliers** (applied independently inside each category):

| Finding position | 1st | 2nd | 3rd | 4th | 5th and later |
| --- | ---: | ---: | ---: | ---: | ---: |
| Multiplier | 1.00 | 0.75 | 0.50 | 0.35 | 0.20 |

**Other rules**

* Categories: Secrets, IAM, Dependencies, SonarCloud.
* IAM findings keep their scanner severity for reporting but are scored as **HIGH**.
* A SonarCloud **Quality Gate failure adds 5 points** (any status other than empty, `UNKNOWN`, `OK`, `PASSED`, `PASS`).
* Category scores are added, rounded and **capped at 100**.

**Risk levels**

| Score | Level |
| --- | --- |
| 0 – 20 | LOW |
| 21 – 40 | MEDIUM |
| 41 – 70 | HIGH |
| 71 – 100 | CRITICAL |

**Example:** 1 secret (10 × 1.00) + 1 IAM wildcard (7 × 1.00) + failed Quality Gate (5) = 22 → MEDIUM. The release is still blocked, because the verdict is decided by the mandatory block conditions, not by the score.

---

## 🚦 Release Decision (ALLOW / BLOCK)

Implemented in `calculate_final_verdict()`.

### 🚫 BLOCK when any of these is true

* A security scanner failed to execute (status `ERROR` / `FAILED`)
* Any secret is detected
* Any IAM wildcard is detected
* A Critical, High, or Medium/Moderate dependency vulnerability is found
* SonarCloud execution failed
* The SonarCloud Quality Gate fails
* Any SonarCloud finding exists

### ✅ ALLOW

No blocking condition is triggered. Low or unknown-severity dependency findings do not block by themselves.

---

## 🧾 Report Structure

`run_security_gate(pr_url, include_details)` returns one dictionary:

```text
report
├── timestamp                scan start time
├── duration_seconds
├── verdict                  ALLOW | BLOCK
├── risk_analysis
│   ├── score, level
│   ├── category_scores      secrets, iam, dependencies, sonarqube
│   ├── calculation[]        category, issue, severity, scoring severity,
│   │                        base points, multiplier, contribution
│   ├── quality_gate_status, quality_gate_penalty
│   └── methodology          severity points, multipliers, IAM scoring note,
│                            quality-gate penalty, rounding, maximum score,
│                            risk thresholds, mandatory block conditions
├── pr_information           repository, owner, repo, title, number, state,
│                            source/target branch, commits, files changed,
│                            additions, deletions, head SHA, URL, status
├── change_information      files changed, additions, deletions, commits, branches
├── scan_summary            status and findings per scan
│                           (dependency: vulnerable_dependencies, vulnerabilities;
│                            SonarCloud: quality_gate, project_key)
└── scans                   secrets, iam, dependencies, sonarqube
                            (each: status + findings[])
```

Each finding in the report contains `file`, `line`, `issue`, `severity`, `reason` and `verdict`, plus `recommendation` when details are enabled, and `id`, `package`, `version` or `rule_name` where applicable. Findings from every scanner are first converted to this common format (`normalize_finding`), and source-code content is not kept.

When `include_details` is off, recommendations are omitted (and for SonarCloud findings the reason is omitted as well).

---

## 🌐 Web Interface

`app.py` serves `templates/index.html`.

* **Input:** PR URL field and a "Show detailed reasons and recommendations" checkbox
* **Validation:** the URL must match `https://github.com/<owner>/<repository>/pull/<number>`; clear messages are shown for an empty URL, an invalid URL and a failed security gate
* **Verdict banner:** ✅ ALLOW or 🚫 BLOCK
* 📋 **Pull Request Information:** title, PR link, PR number, repository, status, source branch, target branch, head SHA
* 📝 **Change Summary:** files changed, lines added, lines deleted, commits, source and target branch
* ⏱️ **Scan Execution Information:** start time, duration, overall verdict
* 🛡️ **Security Scan Summary:** status, finding count and result (PASS / BLOCK) for each check
* Result tables: 🔑 Secret Scan (line, file, type, severity, reason, recommendation), 🔐 IAM Security Scan (line, file, issue, severity, reason, recommendation), 📦 Dependency Vulnerability Scan (line, file, package, vulnerability, severity, reason, recommendation), 📊 SonarCloud Analysis (line, file, issue, type, severity, reason, recommendation)
* 📈 **Risk Assessment:** risk score and level, category risk scores, risk-score calculation table, scoring methodology (severity points, score/level thresholds) and 🚨 mandatory block conditions
* 🧾 **Complete Security Gate Result:** the full JSON report (shown when detailed output is selected)
* Responsive layout

The Flask server runs on `127.0.0.1:5000` with `debug=False`.

---

## 📁 Project Structure

```text
release-portal-security-gate/
│
├── app.py                      # Flask web application
├── templates/
│   └── index.html              # Web interface template
│
├── src/
│   ├── main.py                 # Security gate: scanning, normalization, risk score, verdict, CLI
│   ├── github_client.py        # GitHub API client
│   └── checks/
│       ├── secrets.py          # Secret detection
│       ├── iam.py              # IAM wildcard check
│       ├── cve.py              # OSV.dev dependency scan
│       └── sonarqube.py        # SonarCloud scan
│
├── test_sonar_rule.py          # SonarCloud rule API test script
├── run-sonar.ps1               # Windows SonarScanner helper script
├── sonar-project.properties    # SonarScanner project settings
├── .secrets.baseline           # detect-secrets baseline
├── requirements.txt
├── .gitignore
├── .env                        # Local credentials (not committed)
└── README.md
```

> The uploaded copies of `.gitignore` and `.secrets.baseline` appear as `_gitignore` and `_secrets.baseline`. The exact files may vary slightly depending on the current project version.

---

## ⚙️ Prerequisites

* Python 3.x (`requirements.txt` notes Python 3.14.7 and pip 26.2.1)
* Git (SonarCloud analysis clones the repository)
* SonarScanner CLI 8.1.0.6389
* Java / OpenJDK 21.0.12.1 LTS (for SonarScanner)
* A GitHub token with access to the Pull Requests being analyzed
* A SonarCloud organization, project and token

---

## 📥 Installation

```bash
git clone https://github.com/himanidhawan4/release-portal-security-gate.git
cd release-portal-security-gate
```

**Windows**

```bash
python -m venv venv
venv\Scripts\activate
```

**Linux / macOS**

```bash
python3 -m venv venv
source venv/bin/activate
```

```bash
pip install -r requirements.txt
```

| Package | Version | Purpose |
| --- | --- | --- |
| Flask | 3.1.3 | Web interface |
| requests | 2.34.2 | HTTP calls (GitHub, OSV.dev, SonarCloud) |
| python-dotenv | 1.2.2 | Loads `.env` |
| detect-secrets | 1.5.0 | Secret detection |

SonarScanner CLI and Java are installed separately.

---

## 🔐 Configuration (.env)

Create a `.env` file in the project root. Do not hard-code credentials in the source.

```env
GITHUB_TOKEN=your_github_token
SONAR_TOKEN=your_sonar_token
SONAR_ORGANIZATION=your_sonarcloud_organization
SONAR_PROJECT_KEY=your_sonarcloud_project_key

# Optional: full path to SonarScanner if it is not on PATH
SONAR_SCANNER_PATH=C:\path\to\sonar-scanner\bin\sonar-scanner.bat
```

| Variable | Required | Purpose |
| --- | :---: | --- |
| `GITHUB_TOKEN` | ✅ | GitHub API authentication |
| `SONAR_TOKEN` | ✅ | SonarCloud authentication |
| `SONAR_ORGANIZATION` | ✅ | SonarCloud organization |
| `SONAR_PROJECT_KEY` | ✅ | SonarCloud project key |
| `SONAR_SCANNER_PATH` | optional | Location of SonarScanner |

### ⚠️ Important

Do not commit `.env` or actual credentials to GitHub. It is already listed in `.gitignore`:

```gitignore
.env
```

---

## ▶️ Usage

### Web interface

```bash
python app.py
```

Open `http://127.0.0.1:5000`, enter a PR URL such as `https://github.com/owner/repository/pull/123`, optionally tick *Show detailed reasons and recommendations*, and click **Run Security Gate**.

### CLI

```bash
python -m src.main https://github.com/owner/repository/pull/123
```

The CLI asks whether to include detailed findings, reasons and recommendations (`y/n`), runs the four checks, and prints the report as JSON under `RELEASE PORTAL SECURITY GATE`.

### Individual checks

```bash
python -m src.checks.iam <github-pr-url>
python -m src.checks.cve <github-pr-url>
```

Both print their result as JSON with details enabled. The secret and SonarCloud checks are run through the security gate.

### Windows SonarScanner helper

```powershell
.\run-sonar.ps1
```

---

## 🧰 Helper Files

| File | Purpose |
| --- | --- |
| `sonar-project.properties` | SonarScanner settings: organization `himanidhawan4`, project key `himanidhawan4_release-portal-security-gate-test`, project name `release-portal-security-gate-test`, `sonar.sources=.`, encoding UTF-8 |
| `run-sonar.ps1` | Changes to the project folder, stops running Java processes, removes the old `.scannerwork` directory and runs `sonar-scanner` |
| `test_sonar_rule.py` | Calls the SonarCloud `/api/rules/show` endpoint for rule `text:S8564` using `SONAR_TOKEN` and prints the response |
| `.secrets.baseline` | detect-secrets baseline (version 1.5.0) with the plugin and filter configuration and no recorded results |
| `.gitignore` | Ignores Python cache/build files, virtual environments, `.env`, `.scannerwork/`, IDE and OS files, and `output.txt` |
| `output.txt` | Saved console output from development runs (listed in `.gitignore`) |

---

## 🔒 Security & Privacy

* Tokens and Sonar settings are supplied through environment variables, not written in the source code.
* User information is not stored as part of the assessment workflow.
* Reports contain file, line, issue, severity, reason and recommendation; source lines and secret values are not included.
* The web form validates the PR URL format before running any scan.
* The repository cloned for SonarCloud analysis is placed in a temporary directory and deleted after the scan.
* Keep `.env` local and never commit it.

---

## 🛠️ Technology Stack

**Backend:** Python · Flask · REST APIs · requests · python-dotenv

**DevSecOps / Security:** detect-secrets · OSV.dev · SonarCloud (SonarScanner CLI and Web API) · IAM policy analysis

**Version Control:** Git · GitHub · GitHub REST API

**Tooling:** Java (OpenJDK 21) · PowerShell script · VS Code · Python virtual environment · environment-based configuration

---

## 📌 Limitations

* The release decision depends on the availability and response of GitHub, OSV.dev and SonarCloud.
* Dependency scanning currently covers PyPI (`*.txt` files with `==` pins) and npm (`package.json`, `package-lock.json`).
* Secret, IAM and dependency checks analyze the added lines of the PR diff, and only for files for which GitHub returns a patch.
* The IAM check matches wildcard patterns line by line; it does not evaluate the complete policy.
* SonarCloud analysis requires Git, SonarScanner, Java and the configured SonarCloud project, and can take several minutes (analysis wait limit: 300 seconds).
* The project is a Pull Request security assessment system. It does not provide automated production deployment authorization or a persistent team-based approval workflow.

---

## 🔮 Future Scope

These are future enhancements and are **not part of the current implementation**:

* Automated pre-merge enforcement for Pull Requests
* Jenkins / webhook-based automated triggering
* Cloud deployment of the security gate
* Role-based release approval
* Team-lead deployment authorization
* Persistent storage for organizational release records
* Additional security scanners and policy checks

---

## 🎯 Project Objective

To demonstrate how security checks can be incorporated into a software delivery workflow and how multiple security signals can be combined into a risk-aware release decision.

**Secrets + IAM + Dependencies + Code Analysis → Risk Assessment → Release Decision**

---

## 👩‍💻 Author

**Himani Dhawan**

B.Tech Computer Science Engineering
Guru Tegh Bahadur 4th Centenary Engineering College
GGSIPU

**Project:** Risk-Aware DevSecOps Release Gate

GitHub: `https://github.com/himanidhawan4/release-portal-security-gate`

---

## ⭐ Project Summary

> **A risk-aware DevSecOps security gate that analyzes GitHub Pull Requests using secret detection, IAM analysis, OSV.dev dependency vulnerability scanning and SonarCloud, combines the findings into a risk score, and returns an ALLOW / BLOCK release decision with reasons and recommendations.**

**Detect → Score → Explain → Recommend → Decide** 🔐

---

## Screenshots

![Screenshot 1](screenshots/Screenshot%202026-10-19%20112157.png)

![Screenshot 2](screenshots/Screenshot%202026-10-19%20112210.png)

![Screenshot 3](screenshots/Screenshot%202026-10-19%20112220.png)

![Screenshot 4](screenshots/Screenshot%202026-10-19%20112232.png)

![Screenshot 5](screenshots/Screenshot%202026-10-19%20112239.png)

![Screenshot 6](screenshots/Screenshot%202026-10-19%20112247.png)

![Screenshot 7](screenshots/Screenshot%202026-10-19%20112254.png)

![Screenshot 8](screenshots/Screenshot%202026-10-19%20112301.png)

![Screenshot 9](screenshots/Screenshot%202026-10-19%20112310.png)

![Screenshot 10](screenshots/Screenshot%202026-10-19%20112323.png)

![Screenshot 11](screenshots/Screenshot%202026-10-19%20112333.png)

![Screenshot 12](screenshots/Screenshot%202026-10-19%20112344.png)

![Screenshot 13](screenshots/Screenshot%202026-10-19%20112418.png)

![Screenshot 14](screenshots/Screenshot%202026-10-19%20112429.png)

![Screenshot 15](screenshots/Screenshot%202026-10-19%20112440.png)

![Screenshot 16](screenshots/Screenshot%202026-10-19%20112453.png)

![Screenshot 17](screenshots/Screenshot%202026-10-19%20112504.png)