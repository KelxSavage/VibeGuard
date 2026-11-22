# VibeGuard Security Report

- **Target:** `http://127.0.0.1:8765`
- **Scan type:** `website_passive`
- **Findings:** 5

## 1. [LOW] Missing content-security-policy
- Category: `security_header`
- Location: `website response`
- Evidence: `Header not present in response`
- Recommendation: CSP helps restrict the sources from which browser content may load.

## 2. [LOW] Missing x-content-type-options
- Category: `security_header`
- Location: `website response`
- Evidence: `Header not present in response`
- Recommendation: Set nosniff to reduce MIME-type sniffing risks.

## 3. [LOW] Missing referrer-policy
- Category: `security_header`
- Location: `website response`
- Evidence: `Header not present in response`
- Recommendation: Set an intentional referrer policy to limit referrer data leakage.

## 4. [LOW] Missing permissions-policy
- Category: `security_header`
- Location: `website response`
- Evidence: `Header not present in response`
- Recommendation: Restrict browser features the site does not need.

## 5. [MEDIUM] Website origin uses HTTP
- Category: `transport_security`
- Location: `website response`
- Evidence: `The configured origin is not HTTPS`
- Recommendation: Use HTTPS for public sites and redirect HTTP traffic to HTTPS.

## Notes
- One GET request was made to the exact allowlisted origin.
- No crawling, path probing, form submission, credential testing, or exploitation was performed.
