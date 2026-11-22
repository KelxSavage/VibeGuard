# VibeGuard

Local-first, authorized security scanner. This starter release performs:
- Local source-code secret-pattern scanning (with redaction)
- Passive HTTP security-header checks for explicitly allowlisted URLs
- JSON and Markdown reports
- A deliberately vulnerable local demo site for safe practice

It does **not** exploit findings, use discovered credentials, submit forms, crawl arbitrary links, or modify targets.

## Requirements
- Python 3.10+
- Windows PowerShell (commands below also work with minor changes on macOS/Linux)

## Setup (PowerShell)
```powershell
cd C:\VibeGuard
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run the safe local demo
Open PowerShell window 1:
```powershell
cd C:\VibeGuard
.\.venv\Scripts\Activate.ps1
python demo\server.py
```

Open PowerShell window 2:
```powershell
cd C:\VibeGuard
.\.venv\Scripts\Activate.ps1
python main.py scan-repo demo
python main.py scan-url http://127.0.0.1:8765
```

The demo deliberately contains **fake, nonfunctional** credentials and missing security headers. It is only for local learning. Never replace demo values with real secrets.

## Scan your own source repository
Only scan a repository you own or are explicitly authorized to assess:
```powershell
python main.py scan-repo "C:\path\to\your\project"
```

## Scan a website you control
1. Add the exact origin to `config\scope.json`.
2. Then run:
```powershell
python main.py scan-url https://your-domain.example
```
Only exact origins listed in scope are accepted. The scanner makes a single ordinary GET request and checks response headers. It does not probe paths or attempt authentication bypasses.

## Daily monitoring
Use Windows Task Scheduler to run the same approved commands daily. Start with the demo:
```powershell
python main.py scan-repo demo
python main.py scan-url http://127.0.0.1:8765
```
For production use, schedule only targets you own, keep reports private, and avoid putting credentials in command-line arguments.

## Reports
Reports are written to `reports/` as timestamped `.json` and `.md` files. Secret-like values are redacted. Treat reports as sensitive because file paths and finding details may still reveal project structure.

## Current limitations
This is a starter scanner, not a complete penetration-testing product. Pattern matches can be false positives and cannot prove a credential is active. Header checks are baseline checks, not a full web application security audit.
