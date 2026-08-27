---
title: "Trust the Hostname, Not the Origin: How a Permissive Subdomain Pattern Becomes Code Execution"
author: CipherDrake
date: 2026-07-17
tags: [appsec, bug-bounty, code-injection, cwe-94, xss, client-side, paas, methodology]
status: published
sanitized: true (no target identity, endpoints, parameter names, function names, ids, vendor/product names, or verbatim error strings)
visibility: public
---

# Trust the Hostname, Not the Origin: How a Permissive Subdomain Pattern Becomes Code Execution

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere. No real target, endpoints, parameter names, ids, or vendor identity.

Most access-control write-ups turn on a forgeable object id. This one turns on a forgeable *hostname*, and on a mistake that's easy to make and easy to miss: checking that a URL's host matches an allowed pattern, and treating that match as proof the content behind it is trustworthy.

The target was a consumer web app that inlines a small loader script on every page. The loader fetches page-injection configuration from the app's own internal service and injects the result, markup and JavaScript both, into the live page. The loader also supports an override: a URL parameter that lets an internal QA process point the fetch at a preview deployment instead of production, for testing unreleased experiments before they ship. That override is the whole story. Found by reading the deobfuscated source, not by scanning, confirmed end to end against the live target, no prior authentication required.

## The setup: a legitimate feature, an unchecked assumption

The feature itself is reasonable. Feature-flag and page-injection systems commonly need a way for internal testers to preview a branch deployment before it merges to production: pass a parameter, the loader points itself at the preview build instead of the live config service, everyone gets to see the new experiment before it ships.

The implementation read the override value, checked whether it matched a hostname pattern for the company's chosen deployment platform, a public Platform-as-a-Service that hands out free subdomains to any signup, and if the pattern matched, used that hostname *directly and verbatim* as the base URL for the config fetch. The check was "does this look like a hostname the deployment platform would issue," not "is this a deployment my organization actually owns and controls."

Those are different questions, and the gap between them is the vulnerability.

## Why a hostname-pattern match is not an ownership check

A public PaaS's free subdomain space is, definitionally, open to anyone. Confirming that a string matches `*.some-paas.example` confirms nothing about who registered that particular subdomain. Anyone can stand up a project on the same platform, in minutes, at no cost, and get a hostname that satisfies the exact same regex the loader is checking.

Once that's true, the loader's trust decision collapses to: "if the URL looks like it points at *a* deployment on this platform, treat whatever that deployment returns as authoritative content to inject into the page." An attacker who registers their own project on the same platform satisfies every check the loader performs. There is no signature, no shared secret, no reference back to an allowlist of the organization's *own* known deployment names, nothing that distinguishes "a QA preview we control" from "any project anyone controls."

## The mechanism, end to end

Read from source, then confirmed live, in three stages:

1. **The loader reads an override value from the page URL.** A parameter carries a token that, if it matches the expected shape (a bare subdomain of the PaaS, or a full URL to one), is used as the fetch's base host.
2. **The loader performs a credentialed cross-origin fetch** to that host, requesting the same page-injection config path it would normally request from its own internal service. Because the request includes credentials (cookies), a legitimate response would need to explicitly allow the origin via CORS. An attacker-controlled endpoint has no such restriction to satisfy since the attacker configures the CORS response themselves.
3. **The response is trusted content.** Any markup field in the response gets written into the live DOM. Any script field gets wrapped and executed, with a callback invoked against a real element in the page. There is no second check between "the fetch succeeded" and "run what came back."

The full chain: an attacker-controlled hostname is accepted as the fetch target because it matches a permissive pattern, a credentialed cross-origin fetch is made to that attacker-controlled host, and the response is executed with full page privileges, on the real origin, in front of any visitor who clicks a single crafted link. No stored payload on the target's own infrastructure, no authentication required, and (in the confirmed case here) the visiting session did not need to be logged in.

## Recognition conditions: when to look for this

This pattern is worth checking for whenever a client-side script:

- Reads a URL parameter, hash fragment, or referrer value and uses it to construct a fetch, script `src`, iframe `src`, or redirect target.
- Validates that value against a **hostname pattern** rather than an **exact, hardcoded allowlist** of specific hosts the organization actually controls.
- The pattern permits any subdomain of a *public, self-service* hosting platform (a PaaS, a static-site host, a CDN with vanity subdomains, a URL shortener, anything where "get your own subdomain" is a free, instant signup).
- The fetched or loaded content is then trusted: injected into the DOM, executed as script, used to redirect, or treated as configuration without further validation.

The tell is almost always in innocuous-sounding developer conveniences: "point this at a preview build," "override the config source for QA," "load from a branch deployment." These are legitimate needs. The bug is never the feature; it's validating the *shape* of the hostname instead of the *ownership* of the specific host.

It's also worth noting how this was found: not through fuzzing the parameter, but through reading the loader script itself, end to end, because it looked like the kind of place this pattern hides. A structured endpoint-by-endpoint sweep of the rest of the app (account object-ownership checks, cross-account write attempts, and so on) turned up nothing on this same target; the one real finding came from an unstructured "read this because it's there" pass. Both styles of testing earn their place in a methodology, and this is a good argument for budgeting time for the second one even when the first is running clean.

## Portable lessons

**A hostname-pattern match is not equivalent to a trust decision.** If a value satisfying a regex is enough to make your application treat a remote host as authoritative, ask what actually distinguishes "one of ours" from "anyone who can sign up for the same free service." If the answer is "nothing," that's the vulnerability, independent of what the fetched content is used for.

**Self-registerable subdomain spaces are effectively public, no matter how official the parent domain looks.** `*.your-paas-of-choice.app` looks like it belongs to a serious platform. It does not mean the specific subdomain in front of you belongs to your organization. Treat any wildcard-pattern check against a public hosting platform as equivalent to "no check" for ownership purposes.

**Credentialed cross-origin fetches need a real CORS answer, and the absence of one is informative.** When testing a similar mechanism, a fetch that fails with a CORS error against an *unclaimed* subdomain is often enough to prove the vulnerability mechanically, before ever deploying a working responder. The failure mode itself, "blocked because no CORS header was present," confirms the request went exactly where an attacker's request would go; only the deployed proof-of-concept was still needed to demonstrate full execution.

**Dynamic import/eval of remote content is a second, compounding risk on top of the trust gap.** Once a script is willing to fetch remote JSON and pull a code string out of it to execute, the severity ceiling is "full script execution in the page's own origin," not "content spoofing." Treat any code path that ends in a dynamic `import()`, `eval()`, or Function constructor fed by network-sourced data as a code-injection candidate (CWE-94) even if the surface impact looks like classic reflected script injection.

## Remediation, for the defender reading this

- **Replace hostname-pattern matching with an explicit, hardcoded allowlist** of the organization's own known deployment names or an internally issued, signed token proving a given preview deployment belongs to the organization's own build pipeline.
- **Never send credentials on a fetch whose target host is influenced by client-controllable input.** If an override mechanism is required for internal QA, gate it server-side (a build-time flag, an internal-only route, a signed and short-lived token minted by the organization's own CI) rather than trusting anything reachable from a public URL parameter.
- **Treat any response used to drive DOM injection or dynamic code execution as untrusted by default**, regardless of which host it came from, and validate its shape and content strictly rather than assuming "the host matched, so the payload is safe."
- **Audit every client-side loader, tag-manager snippet, or "point at a preview build" mechanism** for the same pattern: URL-controlled host, permissive pattern match, and credentialed or trusted use of the response. This is a common shape in feature-flag/experimentation tooling generally, not specific to any one platform.

## A reusable checklist

- Read client-side loader/config scripts end to end, not just the endpoints they call. The vulnerability lives in the trust logic, which only shows up in source.
- Any URL-controlled hostname feeding a fetch, script load, or redirect: is the check a hardcoded allowlist, or a pattern that matches a whole public hosting platform's subdomain space?
- If a public PaaS or similar self-service host is in the allowed pattern, assume any subdomain of it is attacker-reachable at zero cost, and test accordingly.
- Confirm the mechanism cheaply first: an unclaimed attacker-style hostname that fails with the *expected* CORS/fetch error is often sufficient proof before standing up any real infrastructure.
- Escalate to a full harmless proof-of-concept (a visible, reversible DOM change, no data access) only once the mechanism is confirmed, and only within program rules.
- Classify by root cause: untrusted-input-controlled code inclusion and execution is Code Injection (CWE-94), even when the observable impact looks like reflected XSS.

## Closing

The bug was never the feature. Letting an internal process preview an unreleased build from a URL parameter is a normal, useful thing to build. The bug is validating that request against "does this look like the platform's hostname shape" instead of "do we actually own this specific host," and then trusting whatever comes back enough to execute it in the application's own origin. That gap is invisible in a black-box endpoint sweep and obvious the moment you read the script that makes the decision. Read the loaders, not just the routes.
