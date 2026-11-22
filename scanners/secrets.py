import re
from pathlib import Path

# Heuristic detectors only. Values are never copied into reports.
PATTERNS = [
    ("OpenAI secret key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("Supabase secret key", re.compile(r"\bsb_secret_[A-Za-z0-9_-]{12,}\b")),
    ("Supabase service-role key/reference", re.compile(r"(?i)\bservice_role\b|\bSUPABASE_SERVICE_ROLE_KEY\b")),
    ("Stripe secret key", re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{12,}\b")),
    ("Stripe restricted key", re.compile(r"\brk_(?:live|test)_[A-Za-z0-9]{12,}\b")),
    ("Private key header", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Generic credential assignment", re.compile(
        r"""(?i)\b(?:api[_-]?key|client[_-]?secret|password|token|secret)\b\s*[:=]\s*["'][^"'\r\n]{8,}["']"""
    )),
]
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".next", "dist", "build", "reports", ".tox"}
TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml", ".env", ".ini",
    ".toml", ".html", ".css", ".md", ".txt", ".sh", ".ps1", ".java", ".go",
    ".php", ".rb", ".sql", ".map", ".conf", ".properties"
}
MAX_FILE_BYTES = 5_000_000

def _redact(value: str) -> str:
    if len(value) <= 8:
        return "[REDACTED]"
    return value[:4] + "…" + value[-3:]

def _finding(title, severity, category, file, line, evidence, recommendation):
    return {"severity": severity, "category": category, "title": title, "file": file,
            "line": line, "evidence": evidence, "recommendation": recommendation}

def scan_repository(root: Path) -> dict:
    findings, scanned, frontend_files = [], 0, 0
    root = root.resolve()
    for path in root.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.relative_to(root).parts):
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
        rel = str(path.relative_to(root))
        if path.suffix.lower() in {".js", ".jsx", ".ts", ".tsx", ".html", ".map"}:
            frontend_files += 1
        for line_no, line in enumerate(content.splitlines(), 1):
            for label, pattern in PATTERNS:
                for match in pattern.finditer(line):
                    findings.append(_finding(
                        label, "high" if ("secret" in label.lower() or "private key" in label.lower()) else "medium",
                        "exposed_credential", rel, line_no, _redact(match.group(0)),
                        "Treat a real exposed credential as compromised: revoke/rotate it, remove it from client code, move it server-side, and clean repository history after rotation."
                    ))
        # Frontend-specific: public env prefixes are not proof of a leak, but server secrets must never use them.
        for line_no, line in enumerate(content.splitlines(), 1):
            if re.search(r"(?i)\b(?:NEXT_PUBLIC|VITE|REACT_APP)_[A-Z0-9_]*(?:SECRET|TOKEN|PRIVATE|SERVICE_ROLE)", line):
                findings.append(_finding(
                    "Potential server secret exposed through frontend environment prefix", "high",
                    "frontend_exposure", rel, line_no, "Frontend-exposed environment variable name detected",
                    "Remove secret material from browser-exposed variables. Public/publishable keys are different from secret or service-role keys."
                ))
            if path.suffix.lower() == ".map" and re.search(r'"sourcesContent"\s*:', line):
                findings.append(_finding(
                    "Source map contains embedded source content", "low", "source_map_exposure", rel, line_no,
                    "Source map includes sourcesContent", "Review whether original source includes sensitive comments, internal endpoints, or accidentally embedded credentials; do not publish maps containing secrets."
                ))
    findings.extend(scan_git_history(root))
    findings.extend(scan_supabase_sql(root))
    findings.extend(scan_api_auth_patterns(root))
    findings.extend(scan_dependencies(root))
    return {
        "scanner": "VibeGuard", "scan_type": "repository_comprehensive", "target": str(root),
        "files_scanned": scanned, "frontend_files_inspected": frontend_files,
        "findings": _dedupe(findings),
        "notes": [
            "Static checks are heuristic and do not prove exploitability or credential validity.",
            "Credential evidence is redacted. Rotate confirmed exposed credentials before history cleanup.",
            "Git history scanning is read-only and limited to the most recent 1,000 commits.",
            "Dependency audit commands may contact package registries; they run only when explicitly available and are not installed automatically.",
            "Live database and authenticated API testing are not performed by this static scan."
        ]
    }

def _dedupe(items):
    seen, out = set(), []
    for item in items:
        key = (item["category"], item["title"], item.get("file"), item.get("line"), item.get("evidence"))
        if key not in seen:
            seen.add(key); out.append(item)
    return out

def scan_git_history(root: Path):
    import subprocess
    findings = []
    if not (root / ".git").exists():
        return findings
    # Git patch output is inspected locally. No checkout, reset, push, or history mutation.
    try:
        proc = subprocess.run(
            ["git", "-C", str(root), "log", "--all", "-1000", "--format=%H", "-p", "-G",
             r"sk-(proj-)?[A-Za-z0-9_-]{20,}|sb_secret_[A-Za-z0-9_-]{12,}|sk_(live|test)_[A-Za-z0-9]{12,}|BEGIN .*PRIVATE KEY|SERVICE_ROLE_KEY"],
            capture_output=True, text=True, errors="replace", timeout=45
        )
        if proc.returncode not in (0, 1):
            return findings
        patch = proc.stdout[:12_000_000]
        commit, file_name = "unknown", "unknown"
        for line_no, line in enumerate(patch.splitlines(), 1):
            if line.startswith("commit "): commit = line[7:19]
            elif line.startswith("+++ b/"): file_name = line[6:]
            elif line.startswith("+") and not line.startswith("+++"):
                for label, pattern in PATTERNS[:6]:
                    if pattern.search(line):
                        findings.append(_finding(
                            "Credential-like value found in Git history", "high", "git_history_exposure",
                            f"{file_name} @ {commit}", line_no, _redact(line.strip("+")[:300]),
                            "Assume the credential may remain compromised even if deleted later. Revoke/rotate it first, then consider a coordinated history rewrite and force-push with repository-owner approval."
                        ))
                        break
    except (OSError, subprocess.TimeoutExpired):
        findings.append(_finding("Git history scan unavailable", "info", "git_history", ".git", None,
                                 "Git command unavailable or scan timed out", "Install Git or run the repository scan again on a smaller repository."))
    return findings

def scan_supabase_sql(root: Path):
    findings = []
    sql_files = list(root.rglob("*.sql"))
    sql_files = [p for p in sql_files if not any(x in SKIP_DIRS for x in p.relative_to(root).parts)]
    if not sql_files:
        return [_finding("No SQL migrations found for Supabase RLS review", "info", "supabase_rls",
                         None, None, "No .sql files found", "Add or select the Supabase migrations directory. This is not proof that RLS is disabled.")]
    for path in sql_files:
        try: text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError: continue
        rel = str(path.relative_to(root))
        creates = list(re.finditer(r"(?is)create\s+table\s+(?:if\s+not\s+exists\s+)?(?:public\.)?([a-zA-Z0-9_]+)", text))
        for match in creates:
            table = match.group(1)
            tail = text[match.end():]
            # Look across file for matching table enable/policy statement.
            if not re.search(rf"(?is)alter\s+table\s+(?:if\s+exists\s+)?(?:public\.)?{re.escape(table)}\s+enable\s+row\s+level\s+security", text):
                findings.append(_finding(f"RLS enable statement not found for table {table}", "high", "supabase_rls",
                    rel, text[:match.start()].count("\n")+1, f"CREATE TABLE {table}", 
                    "Review the table's data sensitivity and enable RLS where appropriate. Add narrowly scoped policies for each required operation."))
            if not re.search(rf"(?is)create\s+policy\b[^;]*\bon\s+(?:public\.)?{re.escape(table)}\b", text):
                findings.append(_finding(f"No policy definition found for table {table} in this migration", "medium", "supabase_rls",
                    rel, text[:match.start()].count("\n")+1, f"CREATE TABLE {table}",
                    "Verify policies exist in other migrations or the live database. Do not add broad USING (true) policies as a shortcut."))
        if re.search(r"(?is)grant\s+all\s+on\s+all\s+tables\s+in\s+schema\s+public\s+to\s+(?:anon|authenticated|public)", text):
            findings.append(_finding("Broad table privileges granted to anon/authenticated/PUBLIC", "high", "database_permissions",
                rel, 1, "GRANT ALL ON ALL TABLES ... TO anon/authenticated",
                "Replace broad grants with least-privilege table/operation grants and rely on RLS as a separate row-level boundary."))
        if re.search(r"(?is)using\s*\(\s*true\s*\)|with\s+check\s*\(\s*true\s*\)", text):
            findings.append(_finding("Unrestricted RLS policy expression detected", "high", "supabase_rls",
                rel, 1, "Policy contains USING (true) or WITH CHECK (true)",
                "Review whether the policy intentionally permits every caller. Prefer ownership, role, and record-state predicates."))
    return findings

def scan_api_auth_patterns(root: Path):
    findings = []
    route_ext = {".py", ".js", ".ts", ".jsx", ".tsx"}
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in route_ext or any(x in SKIP_DIRS for x in path.relative_to(root).parts):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES: continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError: continue
        if not re.search(r"(?i)(@app\.(?:route|get|post|put|delete)|router\.(?:get|post|put|delete)|app\.(?:get|post|put|delete)\s*\()", text):
            continue
        has_auth = bool(re.search(r"(?i)(login_required|require_auth|verify_jwt|current_user|auth\.getuser|getuser\(|authenticate|authorization)", text))
        if not has_auth:
            findings.append(_finding("API route file has no obvious authentication guard", "medium", "api_authentication",
                str(path.relative_to(root)), None, "Route definitions found without common auth markers",
                "Manually review every route. Add authentication where required and enforce object-level authorization on each resource; static markers can miss middleware or gateway enforcement."))
        if re.search(r'''(?i)(cors\s*\(\s*\{\s*origin\s*:\s*['"]\*|Access-Control-Allow-Origin['"]?\s*:\s*['"]\*|(?:response\.)?headers\s*\[\s*['"]Access-Control-Allow-Origin['"]\s*\]\s*=\s*['"]\*)''', text):
            findings.append(_finding("Wildcard CORS configuration detected", "medium", "api_authorization",
                str(path.relative_to(root)), None, "Wildcard origin pattern detected",
                "Use an explicit origin allowlist where browser credentials or sensitive responses are involved. CORS is not authentication."))
        if re.search(r"(?i)(?:req|request)\.(?:params|query)\.[A-Za-z_]+|params\.[A-Za-z_]+", text) and re.search(r"(?i)(?:select|findUnique|findFirst|\.eq\(|\.update\(|\.delete\()", text):
            if not re.search(r"(?i)(owner_id|user_id|created_by|tenant_id|auth\.uid\(|getUser\(|current_user|belongs_to)", text):
                findings.append(_finding("Possible object-level authorization gap", "medium", "api_authorization",
                    str(path.relative_to(root)), None, "Route reads a caller-supplied object identifier without an obvious ownership check",
                    "Verify every object lookup is constrained to the authenticated user's permitted records. Test with two dummy users and attempt cross-account access. Static analysis may miss shared middleware or query helpers."))
        if re.search(r"(?i)jwt\.decode\s*\(", text) and not re.search(r"(?i)(verify\s*[:=]|verify\s*\(|jwt\.verify)", text):
            findings.append(_finding("JWT decode appears without an obvious signature-verification call", "high", "api_authentication",
                str(path.relative_to(root)), None, "jwt.decode detected without common verification markers",
                "Verify token signatures, issuer, audience, expiry, and algorithm using a trusted authentication library. Decoding alone is not authentication."))
    # Supabase Edge Function JWT verification configuration.
    for cfg in root.rglob("config.toml"):
        if any(x in SKIP_DIRS for x in cfg.relative_to(root).parts): continue
        try: cfg_text=cfg.read_text(encoding="utf-8",errors="ignore")
        except OSError: continue
        if re.search(r"(?im)^\s*verify_jwt\s*=\s*false\s*$",cfg_text):
            findings.append(_finding("Supabase Edge Function JWT verification disabled in config", "high", "api_authentication",
                str(cfg.relative_to(root)), None, "verify_jwt = false",
                "Confirm the function is intentionally public. Otherwise enable JWT verification and enforce authorization inside the function. A public endpoint still needs abuse controls."))
    return findings

def scan_dependencies(root: Path):
    import subprocess, json
    findings = []
    manifests = [p for p in [root/"package.json", root/"requirements.txt", root/"pyproject.toml", root/"Pipfile"] if p.exists()]
    if not manifests:
        return [_finding("No recognized dependency manifest found", "info", "dependencies", None, None,
                         "package.json, requirements.txt, pyproject.toml, Pipfile not found",
                         "Add a dependency manifest or select the application root.")]
    if (root/"package.json").exists() and (root/"package-lock.json").exists():
        try:
            proc = subprocess.run(["npm", "audit", "--json"], cwd=root, capture_output=True, text=True, timeout=90)
            data = json.loads(proc.stdout or "{}")
            vulns = data.get("metadata", {}).get("vulnerabilities", {})
            for severity in ("critical", "high", "moderate", "low"):
                count = int(vulns.get(severity, 0) or 0)
                if count:
                    findings.append(_finding(f"npm audit reports {count} {severity} vulnerability/vulnerabilities", 
                        "critical" if severity=="critical" else "high" if severity=="high" else "medium" if severity=="moderate" else "low",
                        "dependency_vulnerability", "package-lock.json", None, f"{severity}: {count}",
                        "Review npm audit details, update to a patched compatible version, run tests, and regenerate the lockfile."))
        except FileNotFoundError:
            findings.append(_finding("npm audit not run: npm is not installed", "info", "dependency_audit", "package.json", None,
                                     "npm executable unavailable", "Install Node.js/npm if you want VibeGuard to run the local dependency audit."))
        except (subprocess.TimeoutExpired, ValueError):
            findings.append(_finding("npm audit could not complete", "info", "dependency_audit", "package-lock.json", None,
                                     "Audit timed out or returned unreadable JSON", "Run npm audit manually in this project and review the result."))
    if any((root/n).exists() for n in ("requirements.txt", "pyproject.toml", "Pipfile")):
        try:
            proc = subprocess.run(["pip-audit", "-f", "json"], cwd=root, capture_output=True, text=True, timeout=90)
            data = json.loads(proc.stdout or "[]")
            dependency_items = data if isinstance(data, list) else data.get("dependencies", []) if isinstance(data, dict) else []
            for item in dependency_items:
                deps = item.get("vulns", [])
                for vuln in deps:
                    findings.append(_finding(f"Known Python vulnerability: {vuln.get('id','unknown')}", "high",
                        "dependency_vulnerability", item.get("name"), None, f"{item.get('name')} {item.get('version')}",
                        "Upgrade to a fixed version listed by the advisory and run the project's test suite."))
        except FileNotFoundError:
            findings.append(_finding("Python dependency audit not run: pip-audit is not installed", "info",
                "dependency_audit", "requirements.txt", None, "pip-audit executable unavailable",
                "Install pip-audit in your own environment to enable advisory checks."))
        except (subprocess.TimeoutExpired, ValueError):
            findings.append(_finding("Python dependency audit could not complete", "info", "dependency_audit",
                "requirements.txt", None, "Audit timed out or returned unreadable JSON", "Run pip-audit manually and review the output."))
    return findings
