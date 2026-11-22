"""Bounded, read-only website checks for explicitly authorized targets."""
import ipaddress
import json
import socket
import ssl
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlunparse
from urllib.request import Request, build_opener, HTTPRedirectHandler

EXPECTED_HEADERS = {
    "content-security-policy": "Define a restrictive Content-Security-Policy that matches the site's required resources.",
    "x-content-type-options": "Set X-Content-Type-Options: nosniff.",
    "referrer-policy": "Set an intentional Referrer-Policy such as strict-origin-when-cross-origin.",
    "permissions-policy": "Disable browser features the site does not need.",
    "strict-transport-security": "For HTTPS sites, configure HSTS after confirming HTTPS works across the domain."
}
EXPOSED_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/.DS_Store", "/backup.zip",
    "/backup.sql", "/config.json", "/config.env", "/debug.log", "/phpinfo.php"
]
USER_AGENT = "VibeGuard/0.4 authorized passive security check"


def _normalize_origin(parsed):
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower().rstrip(".")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Website URL contains an invalid port.") from exc
    if port == (443 if scheme == "https" else 80):
        port = None
    hostpart = f"[{hostname}]" if ":" in hostname else hostname
    netloc = hostpart if port is None else f"{hostpart}:{port}"
    return f"{scheme}://{netloc}"


def _require_public_web_host(hostname, port):
    if port not in (None, 80, 443):
        raise PermissionError("For open-scope checks, only standard HTTP/HTTPS ports 80 and 443 are allowed.")
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".localhost"):
        raise PermissionError("Open-scope mode cannot target localhost or local network services.")
    try:
        addresses = {ipaddress.ip_address(hostname)}
    except ValueError:
        try:
            records = socket.getaddrinfo(hostname, port or 443, type=socket.SOCK_STREAM)
            addresses = {ipaddress.ip_address(record[4][0]) for record in records}
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"Could not resolve public website host {hostname}: {exc}") from exc
    if not addresses or any(not address.is_global for address in addresses):
        raise PermissionError("This hostname resolves to a private, local, or reserved IP address and is blocked in open-scope mode.")


class _SameOriginRedirects(HTTPRedirectHandler):
    def __init__(self, origin):
        self.origin = origin.rstrip("/")

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlparse(newurl)
        destination = _normalize_origin(parsed) if parsed.scheme and parsed.hostname else ""
        if destination != self.origin:
            raise URLError("Cross-origin redirect blocked by VibeGuard scope policy")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _get(url, origin=None):
    req = Request(url, headers={"User-Agent": USER_AGENT})
    context = ssl.create_default_context()
    from urllib.request import HTTPSHandler
    opener = build_opener(
        HTTPSHandler(context=context),
        HTTPRedirectHandler() if origin is None else _SameOriginRedirects(origin)
    )
    try:
        with opener.open(req, timeout=8) as response:
            return response.status, {k.lower(): v for k, v in response.headers.items()}, response.read(4096)
    except HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read(4096)
    except (URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"Could not reach {url}: {exc}") from exc


def _normalize_target(target: str):
    target = target.strip()
    if "://" not in target:
        target = "https://" + target
    parsed = urlparse(target)
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a website URL beginning with http:// or https://.")
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError("Query strings, fragments, and embedded credentials are not accepted. Enter the page URL only.")
    # Reject malformed ports early and normalize an empty path to '/'.
    origin = _normalize_origin(parsed)
    path = parsed.path or "/"
    if not path.startswith("/") or "\\" in path:
        raise ValueError("Enter a valid website path.")
    return parsed, origin, path


def _exposure_probe_urls(origin: str, requested_path: str):
    """Check common exposure paths at the site root and under the requested route."""
    prefixes = [""]
    if requested_path != "/":
        route_prefix = requested_path.rstrip("/") + "/"
        prefixes.append(route_prefix)
    urls = []
    for prefix in prefixes:
        for path in EXPOSED_PATHS:
            candidate = origin + prefix.rstrip("/") + path
            if candidate not in urls:
                urls.append(candidate)
    return urls


def scan_website(target: str, scope_file: Path) -> dict:
    parsed, origin, requested_path = _normalize_target(target)
    config = json.loads(scope_file.read_text(encoding="utf-8"))
    allowed = {str(x).rstrip("/").lower() for x in config.get("allowed_origins", [])}
    explicitly_allowed = origin.lower() in allowed
    if not explicitly_allowed and not config.get("allow_any_public_origin", False):
        raise PermissionError(f"Origin is not allowlisted: {origin}. Add it to config/scope.json only if you own or are authorized to test it.")
    if not explicitly_allowed:
        _require_public_web_host(parsed.hostname, parsed.port)

    target_url = origin + requested_path
    status, headers, _ = _get(target_url, origin)
    findings = []
    for header, recommendation in EXPECTED_HEADERS.items():
        if header == "strict-transport-security" and parsed.scheme.lower() != "https":
            continue
        if header not in headers:
            findings.append({
                "severity": "low", "category": "security_header", "title": f"Missing {header}",
                "file": None, "line": None, "evidence": "Header not present in response",
                "recommendation": recommendation
            })
    if parsed.scheme.lower() == "http":
        findings.append({
            "severity": "medium", "category": "transport_security", "title": "Website origin uses HTTP",
            "file": None, "line": None, "evidence": "The configured origin is not HTTPS",
            "recommendation": "Use HTTPS for public sites and redirect HTTP traffic to HTTPS."
        })

    # Bounded GET-only checks: ten common paths at the origin root and, for a
    # route-specific scan, the same ten paths below that route prefix.
    for probe_url in _exposure_probe_urls(origin, requested_path):
        path = urlparse(probe_url).path
        try:
            code, _, sample = _get(probe_url, origin)
            if code == 200 and sample.strip():
                findings.append({
                    "severity": "high", "category": "exposed_file",
                    "title": f"Potentially exposed file: {path}", "file": path, "line": None,
                    "evidence": f"GET returned HTTP 200 ({len(sample)}-byte sample read, not stored)",
                    "recommendation": "Verify the response is not sensitive. Remove public access to secrets, backups, repository metadata, and configuration files."
                })
        except RuntimeError:
            continue

    return {
        "scanner": "VibeGuard", "scan_type": "website_comprehensive",
        "target": target_url, "http_status": status, "findings": findings,
        "notes": [
            "The exact requested page path was checked for response headers and HTTP status.",
            "Ten common exposed-file paths were checked at the site root and, for route scans, beneath the requested route prefix.",
            "GET-only checks are bounded. No crawling, form submission, credential testing, brute force, exploitation, or state-changing requests were performed.",
            "A 200 response is a signal for manual review, not proof that the file contains secrets."
        ]
    }
