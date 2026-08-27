---
title: "Redirects Don't Need Splitting: Cookie-Path Scoping as the Real CRLF Injection Payload"
author: CipherDrake
visibility: "public"
category: field-note
tags: [ctf, web, crlf-injection, http-headers, cookies, xss, http-smuggling, reverse-proxy]
date: "2026-07-25"
---

# Redirects Don't Need Splitting: Cookie-Path Scoping as the Real CRLF Injection Payload

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

CRLF injection into an HTTP response header is a well-known bug class, and most write-ups about it jump straight to response splitting: inject a fake status line and headers, smuggle a second response onto the wire, and get the victim's browser to render attacker-controlled content. That is the textbook payload. It is also, against a modern browser, usually the wrong payload. Cookies are almost always the better move, and the reason why is worth understanding on its own.

## The setup

A reverse proxy in front of an application had a small, hand-written redirect route: request a path with an identifier in it, get back a `301` whose `Location` header echoes that identifier. Something like:

```
GET /go/<segment> -> 301 Location: /?ref=<segment>
```

Nothing else in the app referenced this route. Its only job was capturing a path segment and reflecting it into a header, and that reflection was never validated for control characters. A raw carriage-return/line-feed in the request line got rejected outright by the proxy with a `400`. Percent-encoded (`%0d%0a`), it sailed through cleanly, because the proxy decodes and normalizes the URI *before* handing the captured value to the code that builds the redirect. Reject-the-literal, accept-the-encoded is the exact signature to test for in any proxy config, load balancer rule, or CDN rewrite that reflects a path or query segment into a generated header. It shows up in `return`, `add_header`, and `proxy_pass`-style directives across most reverse proxies, not just one vendor's.

Confirming the injection is the easy part: request the redirect route with an encoded CRLF followed by a throwaway header name, and watch it appear as its own line in the response.

## Why response splitting is a worse plan than it looks

The instinctive next step is to use the injection point to smuggle a whole second HTTP response onto the connection, so that when the browser's navigation to the redirect target reuses the same keep-alive socket, it consumes the attacker's fabricated response instead of the real one. Two different framing techniques for doing this can both be made to work *on the wire*, verified byte-for-byte with a raw socket tool: overriding the transfer encoding so the proxy interprets a follow-on payload as a second full response, and a version that avoids any encoding conflict at all by padding the first response out to exactly its already-committed `Content-Length` before starting a second, correctly framed response.

Both of those constructions can be proven correct with something like `nc`, and both will still fail against Chrome and any comparably hardened modern browser. The browser will not reuse a connection that still has unread data sitting in its receive buffer once a transaction completes -- it treats that as an unclean connection, closes it, and opens a fresh socket to follow the redirect instead. That is deliberate anti-request-smuggling hardening on the client side, and it kills connection-reuse response splitting categorically, independent of how clean your framing is. The way to confirm this rather than just guess "it's not working" is to open the browser's own network panel and look at the initiator chain for the navigation that follows the injected redirect: if the real page's genuine assets (CSS, JS chunks) load right after it, the browser got the real response, not the injected one.

There is a second, quieter lesson buried in getting to that conclusion: a general-purpose HTTP proxy tool is a well-behaved, spec-compliant client. If you build the same conflicting-framing request and send it through a proxy's own request-repeat feature instead of a raw socket, the proxy will parse the conflicting headers correctly, resolve the ambiguity per the relevant precedence rule, and show you one clean, normalized response -- because that is exactly what a correct HTTP client is supposed to do. That correctness is precisely what makes the tool blind to the bug you're testing for. Framing-level bugs (response splitting, request smuggling) live in the gap between what a byte stream literally contains and what a well-behaved parser reconstructs from it. Test them with something that has no opinions about correctness: a raw socket, not a proxy.

## The payload that actually works: Set-Cookie, scoped by Path

If the header-injection point is real, the better payload is almost always `Set-Cookie`, not a fabricated body. The mechanism depends on two facts most people know individually but rarely put together:

- **RFC 6265 cookie ordering**: when a browser sends multiple cookies with the same name for a request, it orders them from most-specific path to least-specific.
- **First-occurrence-wins parsing**: most server-side cookie parsers, when they see the same cookie name appear twice in an incoming `Cookie` header, keep only the first value and silently discard the rest.

Put those together and you get a scoping trick: inject a `Set-Cookie` header carrying *your own* valid, signed session value, but scope it narrowly with `Path=/some/specific/endpoint`. For every request the victim's browser makes to that one specific endpoint, your cookie is more path-specific than the victim's original session cookie (`Path=/`), so it sorts first and the server-side parser picks it up -- resolving that one request as *you*. Every other request on the same page load, to any other route, still carries the victim's original session cookie unchanged, because your narrowly-scoped cookie simply doesn't match those paths at all.

This matters most when the victim's browser is an authenticated actor you don't otherwise control -- a moderation bot, an admin review process, any headless browser driven by the target application itself. You cannot forge a token bearing their identity, and swapping in your own token wholesale just makes their browser act as you everywhere, which is worthless. Scoping the cookie to a single endpoint is what makes it valuable: it changes the identity of exactly one request while leaving everything else -- including whatever endpoint discloses the thing you actually want -- resolving as the victim.

## Turning self-XSS into cross-identity XSS

The application in question had exactly one place that rendered user-supplied content as raw HTML: a profile page that fetched "your own" profile data and rendered a stored field through an unescaped HTML sink. On its own, that's a well-known trap: it looks like a stored XSS vulnerability, but the fetch is server-side scoped to the authenticated session's own identity, so all it ever renders is your own content back at you. Self-XSS, not exploitable against anyone else -- until the cookie-path-scoping trick changes what "the session's own identity" resolves to for that one fetch.

Once the victim's browser answers the profile-fetch endpoint as you (via the scoped cookie) while continuing to answer every other endpoint as itself, the "self-XSS" sink renders *your* stored payload -- inside a page that is otherwise fully authenticated as the victim. An event-handler-based payload (not a `<script>` tag, since most unescaped-HTML-sink assignments in modern frameworks execute the same way a raw `innerHTML` assignment does, meaning inline `<script>` tags do not run) then executes in that authenticated context and can reach whatever privileged endpoint the victim's identity unlocks -- an identity check, a data export, an admin action -- all without needing to forge or steal a single credential.

## Defensive takeaways

- Any reverse-proxy directive that reflects a captured path or query segment into a generated header (a redirect, a custom header, an upstream proxy target) needs explicit rejection of CR/LF, in both raw and percent-encoded form, applied *after* URL decoding and normalization -- not before.
- Do not rely on browsers refusing malformed response framing as your only defense against response splitting; the underlying header-injection primitive is the actual bug, and it has payloads beyond splitting that current browser hardening does not stop.
- Treat path-scoped duplicate cookies as a genuine authentication bypass primitive, not a curiosity. An application that trusts a session cookie's presence without also validating that its scope and value are exactly what was expected for a given route is exposed to this trick the moment any header-injection point exists anywhere on the same origin.
- Never render user-authored content through an unescaped HTML sink on the assumption that it is only ever "your own" content -- the assumption of "own identity" is exactly the thing a scoped-cookie attack breaks.
- When hunting for or verifying framing-level bugs, use a tool with no opinions about HTTP correctness (a raw socket) rather than a general-purpose proxy, which will silently normalize the exact class of malformed input you're trying to observe.
