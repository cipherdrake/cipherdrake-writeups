---
title: "Field note: client-side JWT secrets and layered access-control gaps"
category: "web"
vulnerability_class: "Broken Access Control (A01) + Cryptographic Failures (A04)"
date: "2026-07-08"
status: "complete"
tags:
  - ctf
  - web
  - owasp
  - bac
  - jwt
  - cryptographic-failures
  - fieldnote
visibility: "public"
---

# Field note: client-side JWT secrets and layered access-control gaps

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

## The shape of it

A client-heavy web app (a JavaScript framework, server-rendered pages plus a JSON API) authorized users with a hand-rolled JWT: HS256, a `role` claim in the payload, carried as both a cookie and a duplicate copy in browser localStorage. Three separate layers made authorization decisions off that token, and each one trusted something different:

1. **Page-level routing/middleware** only checked that *a* token was present. It never verified the signature, so a token whose payload was edited to say `role:admin` — with an invalid signature — was enough to load an admin page.
2. **The admin panel's own client-side visibility check** decoded `role` from the token in the browser and showed or hid the admin UI accordingly. Also bypassable with a forged token, though it read from a slightly different client-side copy of the token than the page gate did (a cookie vs. a localStorage value), which meant defeating one didn't automatically defeat the other.
3. **The backend data API** was more careful — it verified the HMAC signature and rejected both bad-signature forgeries and an `alg:none` downgrade attempt. But its authorization model still boiled down to "trust the `role` claim once the signature checks out" and used it to decide whether to return one user's records or every record in the system, with no independent server-side source of truth for the role.

That third layer is what actually gated the sensitive data — so a forged, badly-signed token got you a rendered admin panel with nothing behind it. The real prize needed a **validly signed** admin token, which meant the signing key itself became the target.

## Where the key was

After exhausting a wordlist crack against the signing secret (a large general password list, a rule-augmented pass, and a wordlist built specifically for JWT secrets — all zero hits), the natural conclusion was "this is a properly random secret, cracking is the wrong approach." That conclusion was wrong. The secret — a readable, illustrative-style string like `Sup3rSecret-App-2025` (not the real value) — was hardcoded directly in a client-side JavaScript bundle, sitting next to the token-signing logic, and was recovered by grepping the downloaded frontend assets for signing-related keywords.

Once recovered, signing a fresh token with `role: admin` and the leaked key produced a token the backend API accepted as fully valid — and the "return everything" branch of its authorization logic had no further check behind it.

## Key lessons

- **A wordlist miss on a signing secret is not proof the secret is random.** For any client-heavy application, a JWT secret that resists a general wordlist, a rule-augmented pass, and a purpose-built JWT-secrets list is a strong signal to go hunting for a hardcoded or leaked key in the shipped frontend bundle — not a signal to conclude the secret is unreachable and move on. Grep the bundle for signing-related logic before assuming "uncrackable."
- **Test each enforcement layer's signature-vs-role behavior separately.** A page gate, a client-side UI visibility check, and a backend data API can each make a different authorization decision off the same token — one might not verify the signature at all, another might verify the signature but not meaningfully check the role. A bypass at one layer does not imply a bypass at the next; map each layer independently before assuming a single forgery carries through the whole app.
- **If a forged client-side value silently reverts, look for a second copy of it.** A client application may store the same piece of authorization state in more than one place (a cookie and a local-storage value, for instance) and re-apply the "real" one on the next action. Overwriting only one copy will look like the forge failed when it actually just got clobbered.
- **Row-level filtering by a client-trusted claim is not the same control as a hard role gate.** An endpoint that quietly changes which records it returns based on an unverified or under-verified claim, rather than outright rejecting unauthorized requests, is a weaker and easier-to-miss version of broken access control — worth testing for even when the endpoint never returns a 401/403 to an unprivileged request.
- **Never ship a signing secret to the client.** If a frontend can construct or verify a token that a backend then trusts, treat anything in that bundle as public information, because it is.

## Remediation, generalized

- Verify token signatures at every layer that makes an authorization decision, including reverse-proxy or framework-level routing/middleware — "a token is present" is not the same check as "this token is valid."
- Keep authorization-relevant claims server-verified against a source of truth (a database record), not just trusted from a client-presented token payload.
- Move privileged-UI visibility decisions server-side; a client-only visibility check is bypassable the moment the client can be made to hold a forged value.
- Treat any secret, key, or credential that ends up in a shipped frontend bundle as compromised. Signing and verification of authorization tokens belongs entirely server-side.
- A single leaked signing key should never be sufficient, by itself, to escalate from a regular user to full administrative visibility across an API. Layer a real role check behind signature verification, not just a claim.
