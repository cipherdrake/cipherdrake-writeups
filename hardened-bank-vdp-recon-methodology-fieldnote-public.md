---
title: "Field note: clearing a uniformly hardened bank VDP (recon methodology, no finding)"
author: CipherDrake
date: 2026-07-22
category: fieldnote
visibility: public
tags: [bugbounty, methodology, recon, vdp, banking, hardened-target, no-finding]
---

# Field note: clearing a uniformly hardened bank VDP

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere. Names no target; all identifying detail generalized and all example values are illustrative.

A write-up of a public VDP engagement against a regional bank that turned out hardened end to end. No vulnerability was found. The value here is not a finding, it is the recon methodology that mapped the whole estate efficiently, the PII-safe way to test a bank's auth boundaries, and the discipline to recognize a finished target and stop rather than file noise.

## The shape of the target

- A bank's public Vulnerability Disclosure Program: no bounty, Gold Standard Safe Harbor, genuinely open scope (any asset the bank owns or operates is in scope, plus a handful of named wildcards).
- Every reachable asset resolved to one of: national electronic-ID authentication (bank-grade eID, no self-serve path for a non-resident researcher), enterprise SSO, bearer-token-enforced APIs, an aggressive WAF, a plain 403, or a hostname that did not resolve publicly.
- The single anonymous input surface was the marketing site's forms, which were output-encoded and server-side validated.

## Recon that worked (reusable)

**1. Verify the scope export, and watch the apex-vs-wildcard gap.**
The program shipped both a CSV and a downloadable proxy scope config. Cross-check that they agree and carry no labeling typo. The subtle trap: HackerOne wildcard exports encode the host as a subdomain-only regex, roughly `^.*\.example\.com$`. That pattern does not match the bare apex `example.com`, because the leading `.*\.` requires at least one label. Browsing the apex made every request read as out of scope: it vanished under the "in scope only" history filter, and the match-and-replace rule that stamps the research header ("only apply to in-scope items") never fired on it. Fix once, up front: broaden each include host to `^(.*\.)?example\.com$` so apex and subdomains both match.

**2. Enumerate subdomains from certificate-transparency logs, not by scanning.**
Open scope on a bank means the footprint is the target, so subdomain discovery is the first real step. Do it against public CT logs, which is OSINT and sends no traffic to the target, keeping you clear of any "no automated scanning" clause. When the usual CT search UI was throwing 502s, a second CT source (a certificate-issuance API) returned a clean, deduplicated list. Then triage: strip shared-certificate artifacts (a marketing-cloud image CDN can drag a hundred unrelated hostnames into one cert), and for any off-brand domain that is not one of the named wildcards, verify ownership before touching it, open scope only covers assets the org actually owns.

**3. Read the CSP header as an asset map.**
A verbose Content-Security-Policy on the main site enumerated the entire third-party integration surface and, more usefully, named an in-scope subdomain that was not linked anywhere else. Free recon, one request.

**4. Enumerate API routes by reading the SPA bundle, not by fuzzing.**
The interesting portal was a single-page app. Its main JavaScript bundle contains every API route the app calls, including the authenticated ones that only fire after login. Pull the bundle and grep it for the route templates (this app used a `<service>-management/<resource>` shape). That produced the full API surface, cleanly, with zero guessing or wordlist traffic. Note: if the bundle looks like it saved wrong and greps empty, check you saved the decoded response body, not the proxy tool's XML item export, and decompress if the stored bytes are still gzip/brotli.

## Auth-boundary testing without touching PII

The non-negotiable rule on a bank: never pull real customer data. That constrains how you test broken access control, and the constraint has a clean solution.

To learn whether an API enforces authentication, hit an endpoint that returns *the caller's own* data (their profile, their own list) with no token. An anonymous caller is nobody, so the response carries no one's personal data regardless of outcome, and the status code alone answers the question:

- `401` with `WWW-Authenticate: Bearer` (or a redirect to login) means auth is enforced. Move on.
- `200` with a body means the customer routes are not enforcing authentication, which is the finding.

Only if step one shows missing auth do you escalate to an object-id route (the IDOR test), and even then you stop and capture the moment real data appears, never enumerating IDs. Here, the staging API returned a uniform `401 WWW-Authenticate: Bearer` across the profile route, a collection route, and an item route, so there was no per-route gap and no reason to touch a single real record. Public reference endpoints (fund/localization data) answered unauthenticated by design and are not findings.

## Verify a client-side rule server-side before calling anything

One form rejected HTML tags in a name field in the browser. That is not a wall, it is a question: is the rule client-side only, or enforced server-side too? Fill the field with a benign value so the in-browser validator passes, intercept the submit, swap the field to the payload in the intercepted request, and forward it past the JavaScript check. Here the server re-validated and rejected it, re-rendering with the same error: defense in depth, no bypass, no reflected XSS. Had the server accepted it, the next check would have been output encoding on the echo or review step.

## Knowing when a target is done

Every reachable in-scope asset resolved to a hardened state. The honest move at that point is to stop, not to manufacture a low-value report to feel productive. Example from this engagement: an internal issue tracker had anonymous access enabled, which sounds like a finding, but the anonymous user could see only an empty system dashboard (no projects, no issues, the project list returned an empty array). Reporting "anonymous can view an empty dashboard" reads as informational and burns Signal for nothing. Recognizing that and closing cleanly is part of the craft.

## The recurring lesson

Flagship, managed, and bank infrastructure is built to resist IDOR and broken-access-control, and it is gated behind eID or SSO almost everywhere. For a first triaged-valid report, bias toward older, smaller, separately-built apps inside scope rather than the primary product. A no-finding engagement is still a win when it leaves behind reusable recon, disciplined negatives, and zero collateral.

## Checklist takeaways

- Broaden HackerOne wildcard scope to include the apex (`^(.*\.)?domain$`) before testing, or the apex silently falls out of scope and your in-scope header rule will not fire.
- Enumerate subdomains from CT logs (multiple sources, since any one can be down); triage shared-cert noise; verify ownership of off-brand domains before touching them.
- Read the CSP header for the asset/integration map; read the SPA bundle for the API route list. Both beat fuzzing and generate no scan traffic.
- Test auth on "returns the caller's own data" routes first: PII-safe, and the status code is the whole answer. Escalate to id-routes only if auth is missing, and stop on the first real record.
- Prove every client-side validation rule is also enforced server-side before you consider it a finding.
- When every asset is hardened, close cleanly. Don't file informational noise.
