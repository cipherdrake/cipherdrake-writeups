---
title: "Field Note: Form Parser Encoding, IP Allowlist Bypass via Headless Bot, and the Explicit Escaping Bypass"
category: "field-note"
technique-class: "stored-xss, command-injection, ip-allowlist-bypass, oob-exfil"
date: "2026-07-13"
tags:
  - ctf
  - web
  - stored-xss
  - command-injection
  - headless-browser
  - oob-exfil
  - form-parser-encoding
  - template-escaping
visibility: "public"
---

# Field Note: Form Parser Encoding, IP Allowlist Bypass via Headless Bot, and the Explicit Escaping Bypass

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

A web challenge that chained four things I needed to have sharper edges on: the encoding behavior of form-body parsers, what IP allowlists actually protect, the difference between a disabled-by-default escape and an explicit bypass, and what a "public listener" actually means on a target with no VPN routing. Notes for the archive in case I see any of these again.

---

## The setup (generalized)

A web app accepted a freeform text field from users, stored the value in memory, and dispatched a headless browser bot to visit a page that rendered all stored values a few seconds later. The rendering was done by a template layer that had its output-escaping explicitly disabled on the stored values. Separately, an internal API endpoint accepted a command string from the URL query parameter and passed it directly to an OS subprocess call with shell expansion enabled. That endpoint was protected only by an IP source check — callers from localhost could reach it, external callers could not.

Two vulnerabilities, one chain: inject a script into the stored field → bot renders it with escaping disabled → script runs in the bot's browser context → bot originates a request to the internal command API from localhost → command execution → out-of-band exfil.

---

## Lesson 1: `+` in a form-POST body is a space, not a concatenation operator

This was the sharpest edge.

The attack had two stages: a Stage 1 probe (a simple outbound beacon) and a Stage 2 chain (fetch the command output, then exfil it to a listener). Stage 1 landed every time. Stage 2 produced zero traffic, even when the command was simplified to something trivially short.

The cause was encoding. `application/x-www-form-urlencoded` — the content type used for standard HTML form submissions — decodes `+` as a literal space character before storing the value. The Stage 2 payload used JavaScript string concatenation:

```javascript
'?d=' + encodeURIComponent(d)
```

The `+` operator was decoded to a space before the string ever reached the template. What got stored was:

```javascript
'?d=' encodeURIComponent(d)
```

A syntax error. The error handler threw silently. No second request ever fired.

Stage 1 had no `+` in it at all, which is why it worked. The `+` inside the URL query string (used to encode a space in the command parameter) was harmless: the form parser decoded it to a space during body parsing, but the browser re-encoded it as `%20` in its own outbound fetch, and the subprocess call received a valid command either way.

**The fix:** template literals. Backtick strings (`\`...\``) are not decoded by `application/x-www-form-urlencoded`. A backtick-string expression like:

```javascript
`?d=${encodeURIComponent(d)}`
```

passes through the form parser untouched. No `+`, no decoding, no syntax error.

**The diagnostic discipline:** when a multi-step payload chain has a Stage 1 that succeeds and a Stage 2 that silently fails, check the stored representation of the payload before diagnosing delivery timing or bot behavior. The `+` problem looks like a timing issue or a bot failure until you notice the Stage 2 JS was already broken before it was ever stored.

For any JS payload that will transit an `application/x-www-form-urlencoded` POST body: avoid `+` entirely. Use template literals for concatenation, and use `%20` for literal spaces in URL components inside the payload string.

---

## Lesson 2: An IP allowlist is not an authorization boundary when the app can proxy the request

The internal command API was gated by IP source. Requests from localhost passed. Requests from any other address were rejected.

This gate did nothing once the injected script ran inside the headless bot's browser context. The bot originated all its requests from localhost — that is how it connected to the application in the first place. The IP check was bypassed not by spoofing or network tricks, but because the request genuinely came from the allowlisted address. The bot was the attacker's execution context on localhost.

This is the same class of bug as server-side request forgery (SSRF), applied at the browser layer instead of the network layer. The headless bot acted as a localhost proxy: the attacker wrote what it fetched, and the internal IP gate trusted the source address unconditionally.

**The recognition condition:** any in-app component that fetches URLs based on user-supplied content — a headless review bot, a thumbnail scraper, a webhook processor, an image importer — collapses any IP-based access control on internal endpoints to nothing for an attacker who can influence what that component requests.

An IP allowlist checks reachability, not identity. Once an attacker can make any trusted-address component act on their behalf, the gate is open.

**The control that would have closed it:** server-side authentication on the internal endpoint — a token, a shared secret, a session check — independent of source IP. IP allowlists can layer defense in depth on top of real authentication; they cannot substitute for it.

---

## Lesson 3: A template filter that disables autoescaping is the misconfiguration, not a missing wrapper

Most modern web templating engines autoescape output by default for HTML contexts. The "missing autoescaping" stored-XSS class is when a developer forgets to configure escaping or uses a template engine that defaults to off.

This challenge was different. Autoescaping was on by default. A specific filter was applied to the user-controlled value to explicitly mark it as safe raw HTML, bypassing the escaping that would otherwise have run. The developer made a deliberate choice to render user input unescaped.

This matters for source review: when auditing a template file for stored-XSS risk, look for the explicit bypass patterns, not just missing escaping. In Jinja2-family engines that would be a raw-output filter on user-controlled values. In Django it would be `mark_safe()`. In React it would be `dangerouslySetInnerHTML`. In Go templates it would be casting to `template.HTML`. The pattern generalizes: wherever output encoding is explicitly disabled, examine what feeds that call, and whether user-controlled data can reach it.

The explicit bypass is often more dangerous than the missing default, because it means the data has been deliberately marked trusted — it will not accidentally get re-escaped by a later layer.

---

## Lesson 4: On public-IP targets, out-of-band exfil requires a public listener

Some challenges expose their container at a public IP and high port rather than inside a VPN-routed lab subnet. In those cases, the attacker's VPN interface address is not routable from the container. A listener on that address will receive nothing, even if the injected code fires correctly.

A public HTTP listener (any service reachable on the public internet) is the fix. Before using one:

- The endpoint URL is the API address that receives requests. The dashboard URL (a single-page app URL, usually with a `#` fragment) is for viewing captured requests in a browser. They are different URLs. Payloads must target the endpoint URL or they will receive zero hits — the SPA fragment is not an HTTP endpoint.
- Confirm the target has outbound internet access before relying on a public listener. Most challenge containers do; some isolated environments do not. A Stage 1 probe to the public listener before building the full chain confirms reachability without wasting the more complex payload.

---

## Summary

Four things worth carrying forward from this one:

1. **`+` in a form-POST body becomes a space.** JS concatenation operators in `application/x-www-form-urlencoded` payloads will silently break. Use template literals. Audit the stored representation of any multi-part JS chain before diagnosing delivery or timing problems.

2. **IP allowlists are reachability checks, not authorization.** Any in-app component that fetches internal URLs on behalf of user-supplied content bypasses internal IP gates by design. Treat it as SSRF at the browser layer.

3. **Explicit escaping bypasses are the misconfiguration to find, not missing defaults.** The raw-output filter, `mark_safe`, `dangerouslySetInnerHTML`, `template.HTML` — wherever escaping is explicitly disabled on user-controlled data, the risk is concentrated.

4. **On public-IP spawns, use a public listener. Endpoint URL, not dashboard URL.**
