import json
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import ssl

EXPECTED_HEADERS = {
    "strict-transport-security": "HSTS helps browsers enforce HTTPS (only relevant on HTTPS sites).",
    "content-security-policy": "CSP helps restrict the sources from which browser content may load.",
    "x-content-type-options": "Set nosniff to reduce MIME-type sniffing risks.",
    "referrer-policy": "Set an intentional referrer policy to limit referrer data leakage.",
    "permissions-policy": "Restrict browser features the site does not need."
}

def _load_scope(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    return set(data.get("allowed_origins", []))

def scan_website(url: str, scope_path) -> dict:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("URL must be an absolute http:// or https:// URL.")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("For this starter version, scan only the exact website origin, without a path/query.")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    allowed = _load_scope(scope_path)
    if origin not in allowed:
        raise PermissionError(
            f"Target not in config scope: {origin}. Add the exact origin to {scope_path} only if you own it or have written authorization."
        )

    request = Request(origin + "/", headers={"User-Agent": "VibeGuard/0.1 (authorized passive security check)"})
    context = ssl.create_default_context()
    try:
        with urlopen(request, timeout=8, context=context) as response:
            status = response.status
            headers = {k.lower(): v for k, v in response.headers.items()}
    except HTTPError as exc:
        status = exc.code
        headers = {k.lower(): v for k, v in exc.headers.items()}
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"Could not reach {origin}: {exc}") from exc

    findings = []
    for header, recommendation in EXPECTED_HEADERS.items():
        if header == "strict-transport-security" and parsed.scheme != "https":
            continue
        if header not in headers:
            findings.append({
                "severity": "low",
                "category": "security_header",
                "title": f"Missing {header}",
                "file": None,
                "line": None,
                "evidence": "Header not present in response",
                "recommendation": recommendation
            })

    if parsed.scheme == "http":
        findings.append({
            "severity": "medium",
            "category": "transport_security",
            "title": "Website origin uses HTTP",
            "file": None,
            "line": None,
            "evidence": "The configured origin is not HTTPS",
            "recommendation": "Use HTTPS for public sites and redirect HTTP traffic to HTTPS."
        })

    return {
        "scanner": "VibeGuard",
        "scan_type": "website_passive",
        "target": origin,
        "http_status": status,
        "findings": findings,
        "notes": [
            "One GET request was made to the exact allowlisted origin.",
            "No crawling, path probing, form submission, credential testing, or exploitation was performed."
        ]
    }
