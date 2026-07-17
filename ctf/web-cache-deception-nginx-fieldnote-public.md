---
title: "Web Cache Deception via Nginx Proxy Cache + Dynamic Content at Static-Extension URLs"
category: "field-note"
technique: "web-cache-deception"
date: "2026-07-13"
tags:
  - web-cache-deception
  - nginx
  - caching
  - web
  - broken-access-control
visibility: "public"
---

# Web Cache Deception via Nginx Proxy Cache + Dynamic Content at Static-Extension URLs

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

---

I worked a web challenge recently that turned on a configuration I had heard named but never triggered in a live context: web cache deception. The setup was a web application behind an nginx reverse proxy with caching enabled, plus a server-side bot feature that made authenticated HTTP requests to attacker-controlled URLs. The vulnerability was not in the application logic -- the authentication was intact, the database was not injectable, and the bot used a plain HTTP client rather than a real browser. The vulnerability was in the cache configuration, one layer removed from the application itself.

## The four conditions

Web cache deception requires all four of these conditions simultaneously:

**1. A reverse proxy or CDN that caches responses by URL without varying on the Authorization (or equivalent session) header.** The cache treats two requests for the same URL as equivalent regardless of who is asking. In nginx this looks like `proxy_cache_valid 200 3m` inside a location block that matches on file extension, with no `proxy_no_cache $http_authorization` or `proxy_cache_bypass $http_authorization` directive present.

**2. A backend route that serves user-specific dynamic content at URLs that look static.** This is the structural mismatch the cache layer cannot see. When a framework catch-all or wildcard route captures requests like `/account/data.js`, the backend serves personalized JSON at a URL the proxy treats as a static asset. The proxy thinks `.js` means cacheable JavaScript; the backend is returning authenticated account data.

**3. A mechanism to make an authenticated user (ideally a privileged one) visit the crafted URL.** This primes the cache with that user's response. In the challenge I worked this was a URL-submission endpoint that fetched attacker-supplied URIs as an authenticated admin user via a server-side HTTP client. In a real engagement it could be a CSRF, a social-engineering link, or any feature that auto-fetches user-supplied URLs server-side.

**4. The attacker can retrieve the cached URL directly.** The retrieval step requires no credentials -- that is the point. If the cache stores the authenticated user's response keyed only to the URL, any subsequent request for that URL returns the same cached response regardless of the requester's identity.

## How the attack chain ran

I registered a low-privilege account to obtain a valid JWT, then submitted a crafted URL to the bot-triggering endpoint. The bot authenticated as admin and fetched the URL. The nginx proxy cached the 200 response -- the admin's full profile including the credential I was after -- keyed to the URL. Roughly five seconds later I made a plain unauthenticated GET to the same URL and received the cached admin response in the body. No external listener, no webhook, no JavaScript exfil. The cache did all the work.

The crafted URL appended a static file extension to a sensitive route path: `/[sensitive-route]/resource.js`. This satisfied the nginx cache location block's extension match and also satisfied the backend's route validation regex.

## Why the backend served content at that URL

The application had a wildcard route that captured path segments including extensions. Any path under the sensitive-route prefix reached the profile-serving handler, which validated the subpath with a regex before returning the profile JSON.

The regex was structurally similar to `re.match(r'.*^resource', path)` in Python. Without the MULTILINE flag, `^` can only succeed at position 0 in the string. For the pattern `.*^resource` to satisfy `re.match`, the `.*` must match zero characters at position 0 (the only position where `^` can fire without MULTILINE), and then `^resource` asserts the path starts with `resource`. The result is that any path beginning with `resource` -- including `resource.js`, `resource/x.js`, and similar -- matches the check. The regex appears to require a specific path prefix while the `.*` prefix is inert; it effectively reduces to `^resource`.

Route validation written this way allows extension appending while appearing to enforce a constraint. This is part of the enabling surface: when a backend will serve dynamic content at `path/x.js`, the cache layer has no way to distinguish it from a genuinely static asset at the same URL.

## What to look for

When a web target includes a reverse proxy and source is available, I now read the cache configuration before I read the application routes. Specifically I check:

- Does the cache location block match on file extension?
- Is there a `proxy_no_cache` or `proxy_cache_bypass` directive conditioned on `$http_authorization` or a session cookie name?
- Is there a `Vary: Authorization` (or `Vary: Cookie`) header on authenticated responses?

If none of those are present and the backend has any wildcard route that could serve authenticated content at a static-extension URL, the web cache deception surface exists.

The bot-triggering endpoint is then not an XSS delivery mechanism -- it is a cache-priming mechanism. This reframing matters: the bot in this challenge used a plain HTTP client, not a browser renderer. Distinguishing between the two changes the entire attack class. A Python `requests.get()` bot with an admin session is exactly what web cache deception needs for the priming step; it is not a target for JavaScript execution. Recognizing which kind of bot is present early saves time on a dead-end XSS path.

## Remediation

Three controls close the nginx-layer half of this attack:

**`proxy_cache_bypass $http_authorization; proxy_no_cache $http_authorization;`** in the nginx cache location block -- any request carrying an Authorization header skips the cache and its response is not stored.

**`Cache-Control: no-store`** (or `private`) on all authenticated API responses from the backend -- instructs every intermediary not to cache the response.

**`Vary: Authorization`** on authenticated responses -- forces compliant caches to maintain separate entries per Authorization value, so an unauthenticated request cannot retrieve a credentialed user's cached entry.

The underlying architectural fix is auditing all wildcard or catch-all routes behind caching proxies. If any route serves user-specific content, that route's responses must not be cacheable at a public cache key. Caching layers are often added to existing applications as a performance afterthought without reviewing which routes now have this property.

## Portable recognition conditions

- A caching proxy in front of a backend with wildcard routing: check whether any authenticated route is reachable at a static-extension URL, then check whether the cache configuration varies on auth headers.
- A URL-submission or bot-triggering endpoint: ask whether the bot uses a real browser (Puppeteer/Playwright -- XSS surface) or a plain HTTP client (requests/httpx/urllib -- cache-priming surface). These are different attacks and the distinction is in the source or behavior, not the endpoint name.
- A path-validation regex without `re.MULTILINE` that uses `.*^anchor`: the `^` cannot succeed after any consumed characters, so `.*` must match zero and the pattern reduces to `^anchor`. Broken anchor logic in path checks allows extension appending while appearing to enforce a prefix constraint.
- No external listener needed when the attacker controls both sides. The request that primes the cache and the request that retrieves it are both direct. Recognize when the attack is fully self-contained within the target: no collaborator infrastructure required means faster execution and no OPSEC exposure.
