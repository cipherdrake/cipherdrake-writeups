---
title: "The Self-Alias Wall: IDOR Testing an API That Never Hands You an Object ID"
date: 2026-07-08
tags: [appsec, bug-bounty, idor, bola, broken-access-control, mass-assignment, methodology, burp]
status: draft (neutral / voice-agnostic — recast into article voice before publishing)
sanitized: true (no target identity, endpoints, field names, ids, vendor/product names, or verbatim error strings)
visibility: public
---

# The Self-Alias Wall: IDOR Testing an API That Never Hands You an Object ID

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere. No real target, endpoints, field names, ids, vendor names, or error strings.

Most IDOR write-ups turn on a forgeable identifier: you find an object id in a URL or body, change it, and read someone else's data. This one is about a target that closes that door by never putting an id in your hands at all, and about how to test that rigorously enough to trust the negative and know when to walk away.

The target was a business web app on top of a hosted identity provider and an API gateway. The plan was broken object-level authorization (IDOR/BOLA), the highest-yield class for a careful manual hunter. Two accounts, a methodical sweep of every per-user endpoint, and at the end: no finding, because the whole API is built on a pattern that makes classic IDOR structurally impossible. Here is the pattern, how to test it, and the lessons that outlast the engagement.

## The setup: two accounts, own-account victim, honest attribution

BOLA testing needs two accounts you control, an attacker (A) and a victim (B). You send requests as A that reference B's objects and watch whether the server lets A touch them. Because both accounts are yours, a positive result exposes only your own second account's data: clean proof, no collateral, nothing to report-and-stop over.

Two practical habits paid off immediately:

- **Run the two accounts in separate browser sessions** (one in the proxy's browser, one in a private window). Short-lived access tokens expire in minutes; keeping both sessions live means a swap test is "send as A, read as B" without a re-login dance every time a token ages out.
- **Attribute traffic as authorized research from request one.** Register with the program's required alias and inject the research header. Note two gotchas: a "only apply to in-scope items" proxy rule will silently skip a backend API host you have not added to your scope, and proxy match-and-replace rules typically do **not** apply to the request-replay tool, so you add the header by hand there. If in doubt, the account itself being registered under the research alias is your baseline attribution.

## The architecture: everything is `me`, nothing is `{id}`

Reading the app's own inline configuration mapped the entire backend for free: the API base paths, the per-service gateway keys, and the extra headers each service wants were all sitting in the page's client-side config. No guessing required. Harvest that before you touch anything.

The shape that emerged, and the whole story:

> Every per-user object, the profile, saved addresses, favorites, and the shopping cart, is fetched through a **self-alias**: a fixed path segment like `/users/me` or `/cart/mine`. The server resolves "who you are" from the bearer token, not from anything in the URL or body. **No response ever contains an object id you could put back into a path.**

That is the defense. Classic IDOR needs an id to forge; here there is nothing to forge, because identity is derived from the token on every call and the object id is never surfaced.

## The hunt: six ways in, six denials

With no id handed to you, the questions become: does a per-id route exist anyway, will the server accept an id you supply, and does any write path trust attacker-controlled input over the token? Tested top to bottom:

1. **Self-alias read, swapped for an explicit id.** Took the `/users/me`-style read and replaced `me` with the caller's *own* object id first (a safe self-read, to learn the route shape). Result: not found. The collection has no per-id route at all; `me` is not shorthand for `/{id}`, it is the only address. The bare collection root (no id) also did not resolve. So there is no read-by-id and no list-all to enumerate.

2. **Parameter override on a token-scoped read.** Some endpoints read identity from the token but will honor an `?id=`/`?userId=` if a developer wired it in carelessly. Appended the victim's id as a query parameter to a self-scoped read. The server returned the *caller's* own record and ignored the parameter. Token wins; the param is decorative.

3. **Mass assignment on profile update.** The profile-write body accepts the fields the form shows. Added the authority fields the form does *not* show (a "verified" boolean, a role string, a customer id) and submitted. The write was accepted, but reading the record back showed those fields unchanged. The server whitelists writable fields and drops the rest.

4. **Cross-account write via a body identifier.** The profile-write body carries the account's own email. Set it to the victim's email while authenticated as the attacker. The server rejected it with an explicit "identity in the token does not match the identity in the request" denial. The write path binds the token identity to the body identity and enforces it. (Bonus: the same endpoint cleanly rejected an expired token, so token lifetime is checked too.)

5. **A second per-user service (favorites/preferences).** Different microservice, different gateway key. Same design: a `/users/favorites` self-alias, token-scoped, no id in the path.

6. **The commerce cart.** Reachable even on an unverified account; adding an item worked. But the cart is returned by `/cart/mine` with no cart id in the body, and asking for `/cart/{my-own-id}` (tried against both id forms the token exposes) returned not found. Self-only, same as everything else.

Six vectors across three separate services (identity, preferences, commerce), every one enforcing per-principal scoping. This is not one well-guarded endpoint; it is a uniform architectural choice.

## Lesson 1: the id you cannot find is the control

The mental model worth internalizing: **an object id is only a lead, never a finding, and an API that never exposes one has removed the lead entirely.** Classic IDOR is "forgeable id plus missing ownership check." This design attacks the first half: identity is derived from the token on every request, and the object id is simply never returned to the client, so there is nothing to tamper. Combined with a write path that binds token-identity to body-identity, the surface that IDOR hunting depends on does not exist.

For defenders, this is the pattern to copy: resolve the acting principal server-side from the session/token, address per-user objects by a `me`/`mine` alias rather than a client-supplied id, and never return a raw object id the client can replay. It is stronger than randomizing ids, because there is no id to guess or capture in the first place.

## Lesson 2: learn the route with your own id before you touch the victim's

When you do have a candidate id-bearing route, test it with your *own* id first. Swapping `me` for your own object id is a zero-risk self-read that tells you whether the route even accepts an explicit id and which id form it wants. Only once you have confirmed the route shape do you escalate to the victim's id. This keeps every negative unambiguous (you know the request was well-formed) and means you never send a cross-account request until you know it could actually work.

A corollary for reading results: when a service sits behind a gateway, a wrong gateway key or a missing required header returns a generic 4xx that is **not** an authorization answer. Match the exact key and headers from a captured legitimate request before you conclude anything from a Repeater response, and isolate any weird edge error with a known-good control request before deciding the edge is blocking you.

## Lesson 3: know when the codebase is telling you to leave

Once the first two per-user endpoints came back token-scoped with no id route, and the write path enforced identity binding, the favorites and cart results were foreseeable: same framework, same authorization model, different service. Worth confirming each (they are different code), but the consistent pattern is itself the signal. **One uniform, well-built codebase does not have a soft corner three endpoints deeper.** The higher-odds move is a *different* codebase: on a large org's scope, an older or separately built app (a partner portal, a rebate or promo app, a regional stack) is far likelier to still be doing `GET /thing?id=123` per-user lookups than the flagship platform that was clearly designed to avoid exactly this.

## A reusable checklist

- Two accounts, both yours, run in separate live sessions. Attribute from request one; add the research header by hand in the replay tool and add the backend API host to your scope.
- Harvest the app's inline client config: API bases, gateway keys, required headers. That is your backend map.
- Screen early: does any per-user response contain an object id you could replay? If not, you are likely facing a self-alias design and the IDOR odds are low.
- Still test it: swap the self-alias for your own id (route shape), then a foreign id (authz); try a param-override on token-scoped reads; try mass-assigning authority fields on writes; try a body-identifier swap on writes.
- Test each verb and each service independently; they are separate code.
- Confirm negatives on the response, and rule out gateway-key/header mistakes and transient edge errors with a known-good control.
- A rigorous negative is a result. Write down *why* it held, then pivot to a different codebase rather than mining the same one.

## Closing

No bug, no payout, one clean verdict and a pattern worth recognizing on sight. A modern API that resolves identity from the token, addresses per-user objects by a `me`/`mine` alias, never returns a replayable object id, and binds token-identity to body-identity on writes has closed the IDOR door by construction. Recognizing that early, testing it thoroughly anyway, and then leaving for a softer codebase is the whole skill. Sometimes the deliverable is knowing when the wall is real.
