# VibeGuard 0.5

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
- Dashboard-based authorized-host manager with host-wide non-standard HTTP(S) port permissions.
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

Manage authorized hosts from the dashboard using **Manage authorized hosts and ports**. Add a DNS hostname once and VibeGuard permits its HTTP(S) scanner to check any port on that hostname. Standard ports 80 and 443 remain available for public hosts when open-scope mode is enabled.

The configuration is stored in `config/scope.json`:

```json
{
  "allow_any_public_origin": true,
  "allowed_origins": [
    "http://127.0.0.1:8765",
    "http://localhost:8765"
  ],
  "authorized_hosts": [
    "pentest-ground.com"
  ]
}
```

- `allow_any_public_origin: true` allows public hosts on standard HTTP/HTTPS ports 80 and 443.
- `authorized_hosts` allows non-standard HTTP(S) ports on each listed hostname. This is host-wide permission, not a port-specific allowlist.
- `allowed_origins` retains exact-origin exceptions such as the bundled local demo.
- Older 0.4.1 `allowed_host_ports` entries are read for backward compatibility and are migrated to the host-wide list when you add a host in the dashboard.
- Localhost and private, link-local, or reserved IP destinations remain blocked in public-host mode, even for an authorized hostname.
- Redirects are followed only when they remain on the same origin; cross-origin redirects are blocked.

Only add systems you own or have explicit permission to assess. Host authorization does not itself grant permission from the system owner.

To disable open public scope, set `allow_any_public_origin` to `false`. Then only exact origins listed in `allowed_origins` are accepted by the website scanner.

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

### Host-wide port permissions and protocol limits

VibeGuard 0.5 authorizes non-standard ports by hostname through the dashboard. Once a host is listed, the website scanner can make its bounded HTTP(S) GET checks on any port from 1 through 65535. The scanner still speaks HTTP(S) only. It does not speak raw TCP protocols such as Redis, SSH, PostgreSQL, or SMTP; listing a host does not add support for those protocols. Keep testing within the target owner's published rules.
