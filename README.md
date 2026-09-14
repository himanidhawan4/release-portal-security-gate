# College_Project
Automated DevSecOps Change Risk Assessment and Remediation Platform :A Python-based system that analyzes software changes, combines security signals, calculates release risk, and provides actionable remediation guidance.

# 🔐 Risk-Aware DevSecOps Release Gate

**Risk-Aware DevSecOps Security Assessment for GitHub Pull Requests**

The **Risk-Aware DevSecOps Release Gate** is a Python-based DevSecOps security assessment system that analyzes a GitHub Pull Request and evaluates security risks before release. It retrieves Pull Request information and changed files through the GitHub API, performs multiple security checks, calculates a risk score, and produces a final security verdict.

### 🔄 Security Assessment Flow

**Detect → Score → Explain → Recommend → Decide**

The system combines security findings from multiple checks into a risk assessment and determines whether the Pull Request should be **ALLOWED or BLOCKED**.

---

## 🚀 Features

* 🔗 Analyze GitHub Pull Requests using a Pull Request URL
* 🐙 Retrieve Pull Request information and changed files through the GitHub API
* 🔑 Detect exposed secrets using **detect-secrets**
* ☁️ Identify overly permissive IAM configurations
* 📦 Scan dependency changes for known vulnerabilities using **OSV.dev**
* 🔎 Perform code-quality/security analysis using **SonarQube Cloud**
* 📊 Calculate a risk score based on security findings
* 🚦 Generate a final security verdict
* 💡 Provide detailed reasons and recommendations when requested
* 🌐 Flask-based web interface for submitting Pull Requests
* 🖥️ CLI support for running the security assessment
* 🔐 Uses environment variables for tokens and service credentials
* 🛡️ Does not store user information as part of the assessment workflow

---

## 🏗️ System Architecture

```text
                    GitHub Pull Request URL
                              │
                              ▼
                    ┌───────────────────┐
                    │   GitHub Client   │
                    │  PR + File Data   │
                    └─────────┬─────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ Security Assessment │
                   └──────────┬──────────┘
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
   │   Secrets   │    │     IAM     │    │ Dependency  │
   │ detect-     │    │  Wildcard   │    │   OSV.dev   │
   │  secrets    │    │   Checks    │    │    Scan     │
   └─────────────┘    └─────────────┘    └─────────────┘
          │                   │                   │
          └───────────────────┼───────────────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │   SonarQube     │
                     │      Cloud      │
                     └────────┬────────┘
                              │
                              ▼
                    ┌───────────────────┐
                    │   Risk Scoring    │
                    └─────────┬─────────┘
                              │
                              ▼
                  ┌────────────────────────┐
                  │     Final Verdict      │
                  │                        │
                  │   ALLOW / BLOCK        │
                  └────────────────────────┘
```

---

## 🔍 Security Checks

### 1. 🔑 Secret Detection

The system uses **detect-secrets** to identify potentially exposed secrets in the Pull Request changes.

Detected secrets contribute to the security assessment and can cause the Pull Request to be blocked.

---

### 2. ☁️ IAM Security Check

The system examines relevant `.tf` and `.json` configuration files for overly permissive IAM policies.

Examples of risky configurations include:

```json
"Action": "*"
```

and

```json
"Resource": "*"
```

Such wildcard permissions are treated as high-risk IAM findings.

---

### 3. 📦 Dependency Vulnerability Scan

Dependency changes are analyzed using the **OSV.dev API** to identify known vulnerabilities.

The project supports dependency ecosystems including:

* npm / `package.json`
* Python / PyPI / `requirements.txt`
* Go
* Maven
* crates.io
* RubyGems

The scanner analyzes dependency changes from the Pull Request and maps identified vulnerabilities to their severity.

---

### 4. 🔎 SonarQube Cloud Analysis

The project integrates **SonarQube Cloud** for code-quality and security analysis.

The SonarQube analysis is considered as part of the overall release decision. A failed or non-acceptable SonarQube result contributes to blocking the Pull Request.

---

## 📊 Risk Scoring

Security findings are converted into a numerical risk score.

Severity values are weighted according to their impact:

| Severity                  | Base Score |
| ------------------------- | ---------: |
| Critical / Blocker        |         10 |
| High                      |          7 |
| Medium / Moderate / Major |          4 |
| Low / Minor               |          2 |

The system also applies severity multipliers when calculating the overall risk and limits the final score to a maximum of **100**.

The resulting assessment represents the combined security risk identified across the different checks.

---

## 🚦 Release Decision

The security assessment produces a final verdict based on the detected security issues.

### ✅ ALLOW

The Pull Request passes the configured security assessment and does not trigger a blocking condition.

### 🚫 BLOCK

The Pull Request is blocked when serious security conditions are detected, such as:

* Exposed secrets
* IAM wildcard permissions
* Significant dependency vulnerabilities
* SonarQube failure/non-acceptable result
* Security scanner errors

The assessment also provides the reasons behind the decision and recommendations when detailed output is enabled.

---

## 🌐 Web Interface

The project provides a Flask-based web interface where users can submit a GitHub Pull Request URL.

The interface provides:

* Pull Request information
* Security check summary
* Risk assessment
* Final verdict
* Scan information
* Detailed reasons and recommendations when selected

### Example Workflow

```text
Enter GitHub PR URL
        ↓
Run Security Gate
        ↓
Retrieve PR Information
        ↓
Run Security Checks
        ↓
Calculate Risk
        ↓
Display Assessment
        ↓
Final Verdict
```

---

## 🛠️ Technology Stack

### Backend

* Python
* Flask
* REST APIs

### DevSecOps / Security

* detect-secrets
* OSV.dev
* SonarQube Cloud
* IAM policy analysis

### Version Control

* Git
* GitHub
* GitHub REST API

### Development

* VS Code
* Python virtual environment
* Environment-based configuration

---

## 📁 Project Structure

```text
release-portal-security-gate/
│
├── src/
│   ├── main.py
│   │
│   ├── checks/
│   │   ├── cve.py
│   │   ├── iam.py
│   │   ├── secrets.py
│   │   └── sonarqube.py
│   │
│   └── github_client.py
│
├── tests/
│
├── requirements.txt
├── README.md
└── .env
```

> The exact files may vary slightly depending on the current project version.

---

## ⚙️ Prerequisites

Before running the project, install:

* Python 3.x
* Git
* GitHub account/repository access
* Required security-service credentials

For SonarQube Cloud analysis, a SonarQube Cloud project and authentication token are required.

---

## 🔐 Environment Variables

Sensitive credentials should **not** be hard-coded in the source code.

Create a `.env` file locally and provide the required credentials.

Example:

```env
GITHUB_TOKEN=your_github_token
SONAR_TOKEN=your_sonar_token
```

Use your own project-specific values.

### ⚠️ Important

Do not commit `.env` or actual credentials to GitHub.

Add it to `.gitignore`:

```gitignore
.env
```

---

## 📥 Installation

Clone the repository:

```bash
git clone https://github.com/himanidhawan4/release-portal-security-gate.git
```

Move into the project directory:

```bash
cd release-portal-security-gate
```

Create a virtual environment:

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Configure the required environment variables before running the application.

---

## ▶️ Running the Application

Start the Flask application using the project's configured entry point.

```bash
python -m src.main
```

The web interface can then be accessed through the local Flask server shown in the terminal.

---

## 💻 CLI Usage

The security gate can also be executed through the Python application.

Provide a GitHub Pull Request URL when prompted:

```text
GitHub Pull Request URL:
https://github.com/owner/repository/pull/1
```

The system then performs the configured security checks and displays the assessment.

---

## 🧪 Security Assessment Output

The generated assessment contains information such as:

```text
Pull Request Information
        │
        ├── Title
        ├── PR URL
        └── Repository information
       
Security Checks
        │
        ├── Secret Detection
        ├── IAM Analysis
        ├── Dependency Scan
        └── SonarQube Analysis

Risk Assessment
        │
        ├── Findings
        ├── Severity
        └── Risk Score

Final Verdict
        │
        └── ALLOW / BLOCK
```

---

## 🔒 Security & Privacy

The project is designed so that user information is not stored as part of the security assessment workflow.

Authentication credentials such as GitHub repository tokens and SonarQube tokens are supplied through environment variables rather than being embedded directly in the source code.

Repository access is therefore performed using the configured authorization credentials, while sensitive credentials should remain local and must not be committed to the repository.

---

## 🎯 Project Objective

The primary objective of this project is to demonstrate how security checks can be incorporated into a software delivery workflow and how multiple security signals can be combined into a risk-aware release decision.

Instead of relying on a single security scanner, the system combines:

**Secrets + IAM + Dependencies + Code Analysis → Risk Assessment → Release Decision**

This provides a consolidated security assessment of a GitHub Pull Request.

---

## 🔮 Future Scope

Possible future improvements include:

* Automated pre-merge enforcement for Pull Requests
* Jenkins/webhook-based automated triggering
* Cloud deployment of the security gate
* Role-based release approval
* Team-lead deployment authorization
* Persistent storage for organizational release records
* Additional security scanners and policy checks

These are future enhancements and are **not part of the current implementation**.

---

## 📌 Limitations

The current project is primarily designed as a Pull Request security assessment system.

The release decision depends on the availability and response of external services such as GitHub, OSV.dev, and SonarQube Cloud.

The current implementation does not provide automated production deployment authorization or a persistent team-based approval workflow.

---

## 👩‍💻 Author

**Himani Dhawan**

B.Tech Computer Science Engineering
Guru Tegh Bahadur 4th Centenary Engineering College
GGSIPU

### Project

**Risk-Aware DevSecOps Release Gate**

GitHub:
`https://github.com/himanidhawan4/release-portal-security-gate`

---

## ⭐ Project Summary

> **A risk-aware DevSecOps security gate that analyzes GitHub Pull Requests using secret detection, IAM analysis, dependency vulnerability scanning, and SonarQube Cloud, then combines the findings into a risk assessment and release decision.**

**Detect → Score → Explain → Recommend → Decide** 🔐
