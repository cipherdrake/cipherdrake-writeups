---
title: "Client-Side Role Gate + Predictable Object ID: SQLi Auth Bypass Chained to a BOLA/IDOR — Field Note"
visibility: public
tags:
  - ctf
  - web
  - sqli
  - auth-bypass
  - idor
  - broken-access-control
---

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

# Client-Side Role Gate + Predictable Object ID: SQLi Auth Bypass Chained to a BOLA/IDOR

A field note distilled from a CTF-style web challenge: a small portal application where reaching the objective required two unrelated vulnerability classes, chained rather than reused. The specifics below are generalized to the vulnerability class; no target names, endpoints, or real values are included.

## The setup

A login form posted a username and password straight to a server-side check, with no CSRF protection and no client-side pre-processing of the credentials. A clean bad-credential attempt returned a server-rendered "invalid combination" error — confirming a real check ran, not a canned response.

## Dead end: the silent single quote

A single quote in the username field, password left alone, came back byte-for-byte identical to the clean bad-credential baseline — no visible error, no length change, no status change. That result is genuinely inconclusive on its own: it could mean the query isn't naively string-concatenated, or it could mean errors are caught server-side and always fall through to a generic "invalid" response regardless of what actually happened underneath. Silence does not, by itself, rule injection in or out.

Lesson: when an error-based probe comes back silent, that is not the same as the field being safe. Follow it with an outcome-based test instead — does a boolean-true payload actually change the result — rather than concluding the injection point is clean from silence alone.

## Vulnerability 1: SQL injection authentication bypass

A classic boolean-bypass payload in the username field (a quote, an always-true condition, and a comment terminator to swallow the rest of the query), with any password, authenticated successfully. The server issued a real session.

This landed on a real, valid, low-privilege account — but not one that had any particular relevance to the objective. A naive `WHERE username=... AND password=...`-style query collapsed by a boolean-true injection typically returns whichever row the database matches first or broadly, not any specific target row. The practical implication: an auth-bypass SQLi of this shape gets you *a* session, not necessarily *the* session you need — plan for a second pivot to reach the actual object you're after, and don't assume the account you land on has the access required.

## Surface discovery: reading the client's own JavaScript

Once inside the app with a low-privilege account, the interesting surface wasn't on the page that rendered — it was in the client-side script backing it. A "records I manage" list rendered without any admin-only actions visible in the UI, and the JavaScript wiring those actions showed why: the click handler that navigated to an edit page was only attached inside an `if (currentUser.isAdmin)` conditional. The logged-in account's admin flag was false, so nothing in the rendered UI was clickable.

That same script also revealed the real target: a predictable, deterministic object-update endpoint (a shape like `/update-<object>/<id>`) keyed by an identifier that turned out to be a straightforward, reversible encoding — base64, in this case — of the target record's own name-like attribute. Entirely public and guessable, not a random or server-generated token.

## Vulnerability 2: broken object-level authorization (BOLA/IDOR)

Two separate questions needed independent answers here, and conflating them would have missed half the bug:

1. **Does the server enforce the role check at all**, independent of the UI? Requesting the update endpoint directly by URL, bypassing the UI entirely, for a record the low-privilege account legitimately owned, returned a full success — confirming the "admin-only" gate seen in the JavaScript was cosmetic. It existed only to decide whether to *attach a click handler*, not whether to *authorize a request*.
2. **Does the server enforce ownership**, independent of role? Computing the identifier for a record the authenticated account had no legitimate relationship to — by encoding a plausible target value the same way the legitimate records were encoded — and requesting it directly also returned a full success, with the complete protected record.

Both questions came back "no protection." That's two independent authorization failures on the same endpoint: no server-side role check, and no server-side ownership check. Either alone would have been a real bug; together, any authenticated low-privilege session could pull or modify any record in the system by simply computing its identifier.

A hidden field returned alongside the leaked record (plausibly intended as some kind of per-record integrity token) turned out not to add any real protection — it was handed back by the server in the very same response that leaked the rest of the record, so it cost nothing extra to obtain and reuse.

Lesson: a hidden or "internal-looking" field disclosed in the same response as the data it's meant to protect provides no defense against reusing that exact disclosure. If an attacker can read the record, they can read whatever token comes bundled with it.

## Why this class matters operationally

Broken access control is consistently one of the most common vulnerability categories found in real production applications — OWASP's own classification has named it the single most prevalent category in recent years. The specific pattern here — a UI-only conditional deciding whether an action is *offered*, with no matching server-side check on whether the action is *authorized* — shows up constantly in real applications: a developer builds the check once for the button, and never separately builds it for the endpoint the button calls. The two controls that would have closed this, in priority order:

- Enforce role and ownership checks **server-side**, on every state-changing and data-returning route, independent of anything the client-side UI decides to render or make clickable. A client-side conditional is a UX decision, never a security boundary.
- Use non-guessable, server-issued identifiers for records reachable through a URL or API path — not a deterministic, reversible encoding of an already-public attribute (a name, an email, a sequential number). If an identifier can be computed from public information, treat it as public.

## Recognition calls worth carrying forward

- A silent result from an error-based probe (a lone quote, a lone special character) is not proof of safety — retest by outcome with a boolean-true payload before ruling anything out.
- An authentication bypass that lands you *a* valid session does not mean it lands you *the* session you need. Check what the session actually has access to before assuming the objective is reached.
- Read the client-side script backing any authenticated page. A conditional that gates a UI action is a strong hint that the equivalent server-side check either exists (verify it) or doesn't (exploit it) — don't assume either without testing the route directly.
- Treat any identifier reachable from a deterministic transform of public data (base64, hex, hashing a known value with no secret salt) as guessable in full. Recompute it for a target outside your own scope and test the route directly.
- Test role-enforcement and ownership-enforcement as two separate questions on the same route. A route can correctly reject the wrong role and still fail on scope, or the reverse — verify each independently rather than assuming one implies the other.
