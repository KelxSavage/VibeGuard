# VibeGuard 0.3

Local-first, loopback-only security review console for assets you own or are explicitly authorized to assess.

## Start
```powershell
cd C:\VibeGuard
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```
Dashboard: http://127.0.0.1:5055

## Included checks
- OpenAI, Stripe, Supabase secret-key patterns and generic credential assignments, with redacted evidence.
- Frontend JavaScript/TypeScript/HTML and source-map inspection, including embedded `sourcesContent` and suspicious frontend environment prefixes.
- Git history scanning for likely credentials in commits, including values later deleted. Read-only; scans up to 1,000 commits.
- Dependency advisories: `npm audit --json` when `package.json` + `package-lock.json` and npm exist; `pip-audit` when installed for Python manifests. These may contact package registries. No tool is installed automatically.
- Supabase SQL migration heuristics: tables without visible RLS enablement/policies, broad grants, and permissive policy expressions.
- API route static heuristics for missing obvious authentication markers, possible object-level authorization gaps, JWT decode without verification, wildcard CORS, and Supabase Edge Function verify_jwt=false.
- Website security headers, HTTPS, and ten bounded common exposed-file GET checks.
- Change tracking: compare each scan with the previous report for the same exact target and scan type, identifying new, resolved, and persistent findings.
- Daily Windows Task Scheduler integration for repeat repository scans.

## Daily monitoring
Run PowerShell as the same Windows user:
```powershell
.\tasks\install_daily_task.ps1 -ProjectPath "C:\Projects\your-app" -Time "09:00"
```
This schedules daily repository scans and records new/resolved/persistent change deltas. It does not schedule remote website checks. Remove with:
```powershell
Unregister-ScheduledTask -TaskName "VibeGuard-Daily-Repository-Scan" -Confirm
```

## Supabase live review
Open `sql\supabase_readonly_audit.sql` in Supabase SQL Editor. It contains SELECT-only queries for RLS state, policies, grants, security-definer functions, and function execute grants. It does not modify your database. Review results manually and test with separate dummy users. Never paste service-role or secret keys into VibeGuard.

## Scope and safety
Website requests follow redirects only when they remain on the exact allowlisted origin; cross-origin redirects are blocked. By default, `config\scope.json` enables `allow_any_public_origin`, so you can enter any public HTTP(S) origin on ports 80 or 443 without editing the allowlist. Open-scope mode blocks localhost and private, link-local, and reserved IP destinations; the exact local demo origins remain explicitly allowlisted. Set `allow_any_public_origin` to `false` to return to exact-origin allowlisting. Only scan sites you own or are explicitly authorized to assess. Website checks use GET only, limited to the origin and ten common file paths. No crawling, fuzzing, brute force, credential stuffing, exploit attempts, or state-changing requests. Repository scans are read-only.

## Important limits
This is an assistive scanner, not a penetration test or compliance certification. Static checks can miss middleware, edge-gateway authentication, policies in other migrations, runtime configuration, and transitive dependency context. Findings require human validation. No automatic fixes, key rotation, Git history rewrite, or database changes occur.
