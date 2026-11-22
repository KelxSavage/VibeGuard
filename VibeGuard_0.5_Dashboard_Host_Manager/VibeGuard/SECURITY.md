# Security Policy

## Authorized use

VibeGuard is intended for local security review of code and passive checks of websites that you own or have explicit permission to assess. Open public scope is a convenience for switching between authorized projects; it is not authorization to test arbitrary third-party systems.

## Reporting a vulnerability in VibeGuard

Please do not publish exploit details or secrets in a public issue. Contact the repository maintainer privately using the contact method listed in the GitHub profile. Include the affected version, reproduction steps, and impact, while redacting tokens, passwords, personal data, and customer information.

## Safe defaults

- The dashboard binds to loopback (`127.0.0.1`) only.
- Open-scope website checks reject private, local, link-local, and reserved destinations and restrict ports to 80/443.
- Website checks use bounded GET requests, do not crawl, and block cross-origin redirects.
- Repository and website scans are read-only. VibeGuard does not rotate credentials, rewrite Git history, or modify databases.


## Authorized host scope

The dashboard's authorized-host list grants the HTTP(S) website scanner permission to connect to any port on each listed hostname. Add only hosts you own or are explicitly authorized to assess. The scanner blocks local/private/reserved destination addresses in public-host mode and restricts redirects to the original origin. This feature does not support raw TCP protocols.
