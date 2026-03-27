# VulnScanner — Android Static Analysis Platform

![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask&logoColor=white)
![MobSF](https://img.shields.io/badge/MobSF-latest-orange?logo=android&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-green)

VulnScanner is a web-based Android APK security analysis platform that automates static analysis using MobSF. It extracts vulnerabilities, permissions, hardcoded secrets, network behavior, and tracker SDKs from any APK file and presents them in a structured, filterable report.

---

## Screenshots

> Add screenshots here

---

## Features

- Drag and drop APK upload
- Automated static analysis via MobSF
- Security score with risk classification
- Vulnerability findings with severity classification (Critical / High)
- Permissions breakdown (Dangerous / Normal / Signature)
- Hardcoded secrets and Firebase URL detection
- Network security analysis and domain inspection
- Tracker SDK detection with category classification
- OWASP Mobile Top 10 mapping
- Scan history with persistent storage
- Multi-page report with tabbed navigation

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | HTML, CSS, Jinja2 |
| Backend | Python, Flask |
| Analysis Engine | MobSF (Mobile Security Framework) |
| Database | SQLite (dev) / PostgreSQL (prod) |
| ORM | SQLAlchemy |

---

## Getting Started

### Prerequisites

- Python 3.10+
- Docker Desktop

### Installation

```bash
# Clone the repository
git clone https://github.com/ABDELthe1/android-vuln-scanner.git
cd android-vuln-scanner

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your MobSF API key

# Start MobSF
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf

# Run the app
python run.py
```

Open [http://localhost:5000](http://localhost:5000) in your browser.

---

## Environment Variables

| Variable | Description | Example |
|---|---|---|
| `MOBSF_API_KEY` | Your MobSF REST API key | `abc123...` |
| `MOBSF_URL` | MobSF base URL | `http://localhost:8000` |
| `DATABASE_URL` | PostgreSQL connection URL (optional, falls back to SQLite) | `postgresql://user:pass@localhost/vulnscanner` |

Copy `.env.example` to `.env` and fill in the values before starting the application.

---

## Project Structure

```
android-vuln-scanner/
├── app/
│   ├── __init__.py          # Application factory and configuration
│   ├── routes.py            # HTTP endpoints (upload, report, history)
│   ├── models.py            # SQLAlchemy ORM models
│   ├── mobsf_client.py      # MobSF REST API wrapper
│   ├── parser.py            # MobSF report normaliser
│   └── comparator.py        # Scan diff utility (Phase 4)
├── templates/
│   ├── base.html            # Shared layout, CSS design system, navbar
│   ├── dashboard.html       # APK upload page
│   ├── report.html          # Tabbed report page
│   └── history.html         # Scan history table
├── uploads/                 # Uploaded APK files
├── docker-compose.yml       # Full-stack orchestration (app + db + MobSF)
├── Dockerfile               # Production container definition
├── requirements.txt
└── run.py                   # Development entry point
```

---

## Vulnerability Detection

VulnScanner surfaces the following classes of issues from MobSF's static analysis engine:

- **AndroidManifest.xml misconfigurations** — exported components, missing intent permissions, and insecure attribute combinations
- **Debuggable and backup-enabled flags** — `android:debuggable="true"` and `android:allowBackup="true"` present in production builds
- **Exported components without permissions** — Activities, Services, and Receivers accessible to any app on the device
- **StrandHogg task hijacking vulnerability** — `taskAffinity` and `launchMode` combinations that allow UI spoofing
- **Insecure network configuration** — cleartext traffic allowed, certificate pinning absent, misconfigured `network_security_config.xml`
- **Hardcoded API keys and credentials** — secrets embedded in source code or resource files
- **Weak cryptography usage** — insecure cipher modes, broken hash algorithms, static IVs
- **Dangerous permission requests** — over-privileged permission declarations flagged by severity
- **Embedded tracker and analytics SDKs** — third-party advertising and analytics libraries identified by signature

All findings are classified as Critical or High and mapped to their corresponding CWE identifiers and OWASP Mobile Top 10 (2024) categories.

---

## Roadmap

- [x] Phase 1: MobSF Docker setup
- [x] Phase 2: MobSF API integration and automated scanning
- [x] Phase 3: Multi-page UI with tabbed report
- [ ] Phase 4: Version comparison (diff two APK scans)
- [ ] Phase 5: CVE enrichment via NVD API
- [ ] Phase 6: Dynamic analysis integration

---

## License

This project is licensed under the [MIT License](LICENSE).
