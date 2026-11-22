# VibeGuard

**Local-first security review console for code repositories and authorized websites.** VibeGuard combines static source checks with bounded, passive website checks. The dashboard runs on your own computer and stores reports locally.

> **Authorization matters:** Only scan websites and repositories you own or have explicit permission to assess. Open public scope removes repetitive allowlist editing; it does not grant permission to test third-party systems.

## Features

- Secret-like credential detection for OpenAI, Stripe, Supabase, and generic assignments, with redacted evidence.
- Frontend JavaScript, TypeScript, HTML, and source-map inspection, including embedded `sourcesContent`.
- Git history scanning for likely credentials in current and earlier commits.
- Dependency advisory checks using `npm audit` and optional `pip-audit` when available.
- Supabase SQL/RLS and database-grant heuristics, plus a separate read-only SQL audit script.
- API static heuristics for authentication markers, object-level authorization, JWT verification, wildcard CORS, and Supabase Edge Function JWT settings.
- Website checks for response headers, HTTPS, and common exposed files.
- JSON and Markdown reports with change tracking for new, resolved, and persistent findings.
- Optional Windows Task Scheduler integration for daily repository scans.

## Run locally (Windows PowerShell)

```powershell
cd C:\VibeGuard
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

Dashboard: <http://127.0.0.1:5055>

The dashboard is intentionally loopback-only. Keep the PowerShell window open while using it.

## Scan a website or a specific page

Enter a full URL or a domain plus path in the dashboard. The scheme defaults to HTTPS when omitted.

Examples:

```text
https://www.chikel2027.com
https://www.chikel2027.com/guestbook
https://www.chikel2027.com/rsvp
www.chikel2027.com/guestbook
```

The scanner requests the **exact page path** you enter and checks that response's HTTP status and security headers. It also makes bounded GET-only checks for ten common accidental-publication paths at the site root and beneath the requested route prefix. For example, a scan of `/guestbook` checks the page itself, root paths such as `/.env`, and route-prefixed paths such as `/guestbook/.env`.

The scanner does not crawl links, submit forms, log in, test credentials, brute-force, fuzz, exploit, or send state-changing requests. It does not scan every route automatically. Submit each page path you want assessed.

Query strings and fragments are intentionally rejected so secrets in URLs are not stored in reports. Enter the clean page URL instead.

## Website scope configuration

`config/scope.json` is configured for any **public** HTTP(S) website on standard ports 80 and 443:

```json
{
  "allow_any_public_origin": true,
  "allowed_origins": [
    "http://127.0.0.1:8765",
    "http://localhost:8765"
  ]
}
```

- `allow_any_public_origin: true` allows public hosts without adding each domain.
- `allowed_origins` is only for explicit exceptions such as the bundled local demo. It can remain unchanged.
- Open scope blocks localhost and private, link-local, and reserved IP destinations, except for exact entries in the explicit allowlist.
- Only ports 80 and 443 are accepted in open-scope mode.
- Redirects are followed only when they remain on the same origin; cross-origin redirects are blocked.

To disable open public scope, set `allow_any_public_origin` to `false`. Then only exact origins listed in `allowed_origins` are accepted.

## Scan a local repository

From the dashboard, enter the full local project folder path. Or use the CLI:

```powershell
python main.py scan-repo "C:\Projects\my-app"
```

Website CLI example:

```powershell
python main.py scan-url "https://www.chikel2027.com/guestbook"
```

## Daily repository monitoring

```powershell
.\tasks\install_daily_task.ps1 -ProjectPath "C:\Projects\your-app" -Time "09:00"
```

This schedules daily repository scans and tracks changes. It does not schedule remote website scans. Remove the task with:

```powershell
Unregister-ScheduledTask -TaskName "VibeGuard-Daily-Repository-Scan" -Confirm
```

## Supabase read-only review

Open `sql\supabase_readonly_audit.sql` in Supabase SQL Editor. The script contains SELECT-only checks for RLS state, policies, grants, security-definer functions, and execute grants. It does not modify the database. Validate findings manually with separate dummy users. Never paste service-role or secret keys into VibeGuard.

## Tests

```powershell
python -m unittest discover -s tests -v
```

GitHub Actions runs the unit suite on Python 3.11 and 3.12 for pushes and pull requests.

## Important limitations

VibeGuard is an assistive scanner, not a penetration test or compliance certification. Static checks can miss middleware, edge gateways, runtime authorization, RLS policies defined elsewhere, and transitive dependency context. A 200 response on a common exposed-file path is only a manual-review signal, not proof of sensitive content. Dependency audit commands may contact package registries. Findings require human validation.

No automatic fixes, key rotation, Git history rewrite, or database changes occur.

## Repository contents

- `app.py`: local Flask dashboard
- `main.py`: command-line entry point
- `scanners/`: repository and website scanners
- `engine/`: report generation and change tracking
- `config/scope.json`: website scope policy
- `sql/`: read-only Supabase audit queries
- `tasks/`: Windows daily scan scripts
- `tests/`: automated regression tests
- `.github/workflows/`: GitHub Actions tests

### Non-standard ports for authorized training labs

Open-scope mode permits normal HTTP/HTTPS ports 80 and 443 on public hosts. A non-standard web port must be enabled as an exact hostname + port pair in `config/scope.json`, under `allowed_host_ports`. The starter configuration includes Pentest-Ground's published HTTP(S) lab ports only: 81, 4280, 5013, 7001, and 9000. This does not enable arbitrary ports on arbitrary hosts.

Example target inputs:

- `https://pentest-ground.com:4280/`
- `https://pentest-ground.com:5013/`
- `https://pentest-ground.com:9000/`

VibeGuard's website scanner only makes bounded HTTP(S) GET requests. It does not speak raw TCP protocols, so Redis on port 6379 is not supported by this scanner. Keep testing within the lab provider's published rules.
