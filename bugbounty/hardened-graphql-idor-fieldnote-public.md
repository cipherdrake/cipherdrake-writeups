---
title: "Anatomy of a Clean No-Find: Manual IDOR Recon Against a Hardened GraphQL API"
date: 2026-06-14
tags: [appsec, bug-bounty, idor, graphql, broken-access-control, methodology, burp]
status: draft (neutral / voice-agnostic — recast into article voice before publishing)
sanitized: true (no target identity, endpoints, operation names, ids, vendor names, or verbatim error strings)
visibility: public
---

# Anatomy of a Clean No-Find: Manual IDOR Recon Against a Hardened GraphQL API

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere. No real target, endpoints, ids, vendor names, or error strings.

Most write-ups document a bug. This one documents the *absence* of one, because the absence was earned and the method getting there is the reusable part.

The target was a consumer marketplace with a Relay-style GraphQL API. The plan was broken object-level authorization (IDOR): the highest-yield class for a careful, manual, by-hand hunter, and the one where a single missed ownership check leaks or rewrites other users' data. Two accounts, a methodical sweep of every object-id-bearing operation, and at the end, five vectors tested, five clean denials. The API's authorization holds.

A clean no-find is a real result. "I proved this is secure" is a different statement from "I didn't find anything," and the difference is whether your testing was rigorous enough to trust the negative. Here's how to make it rigorous, and the three lessons that outlast the engagement.

## The setup: two accounts and honest attribution

IDOR testing needs two accounts you control: an attacker (A) and a victim (B). You forge requests as A that reference B's objects, and you watch whether the server lets A touch them. Both accounts are yours, so there's no collateral and nothing to clean up beyond your own test data.

Attribute your traffic as authorized research from the first request. Register test accounts with whatever alias the program requires, and inject a research-identifying header on every request. The mechanics of that header injection turned into the first lesson (below).

## Lesson 1: getting a manual hunt past modern anti-bot

The target stacked three defensive layers, and you'll meet this combination constantly on anything consumer-facing:

- A **CDN-level JS challenge** (the "checking your browser" interstitial).
- A **behavioral anti-bot SDK** that fingerprints the browser and mints a fresh per-request token.
- A **device/fraud-fingerprint token** attached to sensitive writes.

The intercepting proxy's *embedded* browser tripped the behavioral layer immediately: login was blocked as suspected automation. The fix that unlocked everything:

> **Authenticate in a real, native browser with the proxy off, then bridge the established session into the proxy for testing.**

A real browser presents a clean TLS and runtime fingerprint, so it passes the challenge. Once the session exists, the per-request anti-bot tokens are minted by the live page, and the proxy rides along on requests the browser is already making. Use a proxy-toggle extension so you flip between "direct" (to authenticate) and "through the proxy" (to test) in one click.

The downstream consequence of per-request anti-bot tokens: **request replay is dead.** Capturing a request and re-sending it later from a replay tool fails, because the anti-bot token (and often a short-lived auth token) has gone stale. Which forces the technique in Lesson 3.

## Reading the API: forgeable global IDs

A single authenticated request exposed the whole shape: a Relay-style GraphQL endpoint, authentication by short-lived signed JWTs in httpOnly cookies, and the keystone, **global object IDs were base64 of `"<TypeName>:<integer>"`.**

```
# the authenticated user's own id, base64-decoded (illustrative values):
VXNlck5vZGU6MTIzNDU2Nzg=   ->   UserNode:12345678
```

That is trivially forgeable. To reference any other object you decode it, change the integer, and re-encode. The integers were near-sequential, too, so enumeration would be easy. At this point it *looks* wide open.

It isn't, and that gap, between "the id is forgeable" and "the request is authorized," is the whole story.

## The hunt: five vectors, five denials

With id-forging free, the only question left is whether the server checks ownership when you hand it a forged id. Tested top to bottom:

1. **Read queries** were scoped to the authenticated principal (`me { ... }`-style) and took no id argument at all. There is nothing to swap, because the server derives "who you are" from the session, not from a parameter. Correct by construction.

2. **Update-an-object-by-id** (e.g., updating a saved address). Forged the victim's object id from the attacker's session. The server returned `null` and changed nothing. Owner-scoped.

3. **The generic `node(id:)` fetch.** Relay commonly exposes a top-level `node(id:)` that returns any object by global id, a juicy single point for mass read-IDOR if it isn't authorization-checked per type. Here it returned `null` for a foreign id, and `null` even for the caller's *own* id on the types I held, so the interface simply didn't resolve those types. No generic read path. (Schema introspection was disabled, so enumerating which types `node` *does* resolve wasn't possible without owning more object types.)

4. **Update-a-listing** (the marketplace write, a different resolver from the account-level ones). Replayed the victim's full, valid update payload from the attacker's session with one field changed as a marker. Response: **403, an explicit "not authorized to modify this object" denial.** Not an ambiguous null.

5. **Delete-a-listing** via a bulk action. Delete is worth testing separately, because it's a distinct resolver and delete-authorization is a classic place teams forget the check that update has. Forged the victim's listing id: **an explicit "not authorized for this object" error.** The victim's listing survived.

Five for five. Authorization is enforced at the resolver, consistently, across both account-level and marketplace code paths.

## Lesson 2: the proxy is lying to you, verify on the response

This one cost the most time and is the most broadly useful.

An intercepting proxy's HTTP history shows you the request **as the browser sent it**, *before* any modification you applied downstream (match-and-replace rules, session-handling rules, or even an intercept-and-edit). So when you tamper an id and then read the request back in the history view, you can see the *original* value and conclude "my edit didn't apply," when in fact the edited version went out on the wire.

I burned three separate detours on this, convinced header injection and id-swaps "weren't firing," because I trusted the request shown in history.

> **The response is the only source of truth.** Confirm your tamper took effect by what the server says back, not by what the proxy shows you in the request pane.

A corollary: if a header-injection rule won't apply, stop fighting it and use a session-handling rule, then verify in the proxy's session tracer rather than the history. And strip credentials from *both* directions when sharing captures: request cookies *and* `Set-Cookie` response headers (a long-lived refresh token will happily ride out in a response you paste somewhere).

## Lesson 3: when replay is dead, intercept-and-edit a live request

Because the anti-bot and auth tokens are per-request and short-lived, the only reliable way to send a tampered request is to **edit it live, in flight**, so all the fresh tokens the browser just minted ride along:

1. Scope the proxy's interception rule to the single operation you're targeting (match on the operation name) so only that one request pauses. Otherwise you stall every background call and hit the client's request timeout.
2. Trigger the action in the browser.
3. When the proxy pauses on your operation, edit the object id (or paste a whole prepared body), and forward.
4. Read the response.

To remove all ambiguity on a write test, capture the victim's *own* valid payload first (everything legitimate: their object id, their references), then replay that exact payload from the attacker's session with one marker field changed. Now the only variable is the actor. If it saves, that's a clean authorization break; if it's rejected, that's a clean negative with no field-mismatch noise to misread.

## Why it all held: the check is the control, not the id

The lesson under the lessons: **a forgeable identifier is harmless if the resolver verifies ownership.** This API handed out trivially guessable, sequential, base64-wrapped ids, and it didn't matter, because every state-changing and object-reading path confirmed the authenticated principal was allowed to touch that specific object before doing anything.

That's the correct mental model for both sides of the table. As a hunter, "the id is exposed/guessable/sequential" is a *lead*, not a finding; the finding is the missing check. As a defender, obscuring or randomizing ids is defense-in-depth at best; the actual control is server-side, per-object, per-verb authorization on every request. Enforce it at the resolver, not the route, and test *each verb independently* (read, update, delete), because they're often separate code.

## A reusable checklist

- Two accounts (attacker + victim), both yours. Attribute traffic from request one.
- Authenticate native (proxy off) to clear anti-bot, then bridge the session into the proxy.
- Map object-id encoding before swapping anything (raw int vs UUID vs base64 global id). Forge from a known-good value.
- Enumerate every operation that takes an explicit id, especially mutations. Test read, then write, then delete, separately.
- Replay tools fail against per-request tokens; tamper live via scoped interception instead.
- Verify on the **response**, never the proxy's request history.
- Capture the victim's valid payload and replay it as the attacker to isolate the authorization check.
- A rigorous negative is a result. Write down *why* it held.

## Closing

No bug, no payout, one clean verdict and three durable lessons. The reflexes built here make the next target faster: bridging anti-bot, tampering live, trusting the response over the proxy, and reading a forgeable id as a lead rather than a finding. Sometimes the deliverable is the method.
