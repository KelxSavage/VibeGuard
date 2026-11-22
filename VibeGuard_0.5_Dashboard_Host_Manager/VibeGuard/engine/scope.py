"""Validation helpers for VibeGuard's authorized-host scope."""
import ipaddress
import re


def normalize_authorized_hostname(raw: str) -> str:
    host = raw.strip().lower().rstrip(".")
    if not host or len(host) > 253 or any(ch in host for ch in "/:@?#\\"):
        raise ValueError("Enter a hostname only, without a scheme, port, path, or credentials.")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("That hostname is not valid.") from exc
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".localhost"):
        raise ValueError("Localhost entries are not allowed in public-host scope.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Enter a public DNS hostname, not an IP address.")
    labels = host.split(".")
    if len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        raise ValueError("Enter a valid fully-qualified DNS hostname, such as lab.example.com.")
    return host
