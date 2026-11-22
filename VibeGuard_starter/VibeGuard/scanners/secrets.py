import re
from pathlib import Path

# These are deliberately broad indicators. Matches are redacted and require human review.
PATTERNS = [
    ("OpenAI-style secret", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b")),
    ("Supabase secret key", re.compile(r"\bsb_secret_[A-Za-z0-9_-]{12,}\b")),
    ("Supabase service-role reference", re.compile(r"(?i)\bservice_role\b|\bSUPABASE_SERVICE_ROLE_KEY\b")),
    ("Stripe secret key", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{12,}\b")),
    ("Private key header", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Generic credential assignment", re.compile(
        r"""(?i)\b(?:api[_-]?key|client[_-]?secret|password|token)\b\s*[:=]\s*["'][^"'\r\n]{8,}["']"""
    )),
]

SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".next",
    "dist", "build", "reports"
}
TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml",
    ".env", ".ini", ".toml", ".html", ".css", ".md", ".txt", ".sh",
    ".ps1", ".java", ".go", ".php", ".rb", ".sql"
}
MAX_FILE_BYTES = 2_000_000

def _redact(value: str) -> str:
    if len(value) <= 8:
        return "[REDACTED]"
    return value[:4] + "…" + value[-3:]

def scan_repository(root: Path) -> dict:
    findings = []
    scanned = 0

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_EXTENSIONS and path.name not in {".env", "Dockerfile"}:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        scanned += 1
        for line_no, line in enumerate(content.splitlines(), start=1):
            for label, pattern in PATTERNS:
                for match in pattern.finditer(line):
                    findings.append({
                        "severity": "high" if "private key" in label.lower() or "secret" in label.lower() else "medium",
                        "category": "possible_secret",
                        "title": label,
                        "file": str(path.relative_to(root)),
                        "line": line_no,
                        "evidence": _redact(match.group(0)),
                        "recommendation": (
                            "Confirm whether this is a real credential. If exposed, revoke/rotate it, "
                            "remove it from the client bundle and Git history where appropriate, "
                            "then load it from a server-side environment variable."
                        )
                    })

    return {
        "scanner": "VibeGuard",
        "scan_type": "repository",
        "target": str(root),
        "files_scanned": scanned,
        "findings": findings,
        "notes": [
            "Pattern matches are indicators, not proof that a credential is valid.",
            "No discovered credential was used or transmitted."
        ]
    }
