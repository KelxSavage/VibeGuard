# VibeGuard Security Report

- **Target:** `/mnt/data/VibeGuard/demo`
- **Scan type:** `repository`
- **Findings:** 2

- **Files scanned:** 2

## 1. [HIGH] OpenAI-style secret
- Category: `possible_secret`
- Location: `index.html`, line 9
- Evidence: `sk-p…890`
- Recommendation: Confirm whether this is a real credential. If exposed, revoke/rotate it, remove it from the client bundle and Git history where appropriate, then load it from a server-side environment variable.

## 2. [HIGH] Supabase secret key
- Category: `possible_secret`
- Location: `index.html`, line 10
- Evidence: `sb_s…789`
- Recommendation: Confirm whether this is a real credential. If exposed, revoke/rotate it, remove it from the client bundle and Git history where appropriate, then load it from a server-side environment variable.

## Notes
- Pattern matches are indicators, not proof that a credential is valid.
- No discovered credential was used or transmitted.
