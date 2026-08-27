---
title: "Reading a Host by Differential: Baselines, Header Oracles, and Knowing When an Oracle Has Died"
author: CipherDrake
date: 2026-07-30
tags: [appsec, bug-bounty, recon, methodology, http, reverse-proxy, service-mesh, burp, intruder]
status: published
sanitized: true (no target identity, hostnames, endpoints, ids, error strings, or assembled stack profile)
visibility: public
---

# Reading a Host by Differential: Baselines, Header Oracles, and Knowing When an Oracle Has Died

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere. No real target, hostnames, endpoints, ids, or error strings.

A day of unauthenticated recon against three hosts produced no vulnerability. It produced something more reusable: a working method for reading a host you cannot see inside of, built entirely out of differences between pairs of requests.

The thing worth internalising is that almost nothing here came from reading a response. It came from comparing two responses that differed by exactly one variable. Every real conclusion of the session arrived that way, and every wrong conclusion came from reading a single response on its own and believing it.

## Lesson 1: a response means nothing until you have a baseline

The session opened with a path that returned `403` and a large branded HTML error page. The obvious read is "this endpoint exists and is refusing me." That read is worth precisely nothing, because at that moment there was a sample size of one.

The correcting move costs one request: send the same method, headers, and body to a path that certainly does not exist.

```
POST /nonexistent-<researcher-handle>-baseline
```

If the nonsense path returns the same status, the same content type, and the same byte length, then the original path is not special and you have learned nothing about it. If the nonsense path returns something *different*, the original path is special-cased and now you have a real finding-shaped fact.

In this case the baseline came back as a small JSON `404` while the path under test returned a large HTML `403`. Different status, different content type, different length, and a visibly different header set. That difference is what proved the path was intercepted rather than merely unrouted. No amount of staring at the original 403 would have produced that conclusion.

**Generalise it:** before you interpret any anomalous response, generate the boring one. `content-length` and `content-type` are usually the entire diagnostic, and you can read both without looking at a single byte of body.

## Lesson 2: headers are a better oracle than status codes

Status codes are chosen by whichever layer answers. Headers tell you *which layer that was*, and that is the more useful fact.

Modern deployments frequently sit behind a sidecar or edge proxy that stamps its own headers. The most widely deployed example is a service mesh proxy's upstream-timing header, commonly `x-envoy-upstream-service-time`. The critical semantics, which are easy to get wrong:

> The proxy sets an upstream-timing header **only when it actually forwarded the request to a backend and got a response.**

That gives you a three-state read from the header set alone:

| signature | meaning |
|---|---|
| proxy request-id present, upstream-timing present | a backend service answered |
| proxy request-id present, upstream-timing absent | the proxy itself answered without contacting a backend |
| neither present | something in front of the proxy answered |

That middle row is the valuable one. A proxy answering by itself means either no route matched, or an authorization filter denied the request before routing. Both are structurally interesting and neither is visible in the status code.

The same logic exposed something else on a different host: a `200` that carried object-storage response headers (a request-id from the storage service, a server-side-encryption header, a weak ETag) and *lacked* the security-header set that every other response on that hostname carried. One hostname, two origins, selected by path. That is not deducible from status codes. It is sitting in plain sight in the header block.

**Generalise it:** diff header *sets*, not just header values. A header that is present on one response and absent on another is telling you the two responses came from different places.

## Lesson 3: try to kill your own conclusion before you build on it

Partway through, a family of paths all returned an identical bare `401` with an empty body. The tempting read: these are real routes sitting behind an authentication gate, and that is a map of the API.

Before accepting it, one request:

```
POST /<something>-<researcher-handle>-definitely-not-a-route
```

with the same substring that all the 401-returning paths shared. It returned `401` too.

That killed the conclusion outright. The rule was matching a lowercase substring anywhere in the path, method-agnostic, before any routing decision. Every one of those 401s was the rule firing, and the entire "map of the API" carried zero routing information.

Two supporting details from the same sequence, both worth carrying:

- **The rule was case-sensitive.** The same word with a capital letter fell straight through to the normal backend 404. Case sensitivity in a deny rule is a real bypass primitive in other circumstances, and it is one request to test.
- **The rule was host-scoped, not zone-wide.** The same path on a sibling hostname in the same zone was not intercepted at all. A rule observed on one host tells you nothing about its neighbours. Test each one.

**Generalise it:** the negative control is the cheapest thing in recon and it is the only thing standing between you and forty minutes of enumeration against a rule rather than a route.

## Lesson 4: know when your oracle has died

Having established a response differential, the natural next step is to enumerate against it. That step deserves one more check first: **confirm the differential still holds for something you already know is real.**

Two paths that the application's own client-side configuration declared as live API endpoints were tested. Both returned the same failure signature as a nonsense path. Byte-identical, in fact.

That killed the oracle. If a known-live route and a known-dead route are indistinguishable, the differential cannot classify anything, and an enumeration run would have produced a long column of identical results that looked like data and was not.

It also produced a second discipline point. The failure signature was an upstream connection error, which can be a transient outage rather than a configuration state. Re-testing the same path five hours later returned the identical response, which ruled out the transient reading. **A time-separated re-test is the control for "is this a state or a blip," and it costs one request.**

**Generalise it:** before enumerating against a signature, validate it against a known positive and a known negative. If both come back the same, stop. You do not have an oracle, you have a constant.

## Lesson 5: capture, do not construct

This recurred so many times in one session that it stopped being a tip and became the governing principle.

A hand-crafted probe carries your assumptions about the request shape: the headers, the content type, the method, the path convention. Every one of those assumptions is a variable you have introduced, and every one of them can produce a result you then misread.

The application will hand you a correct request for free. Load the app through a proxy, filter the history, and take the real one.

Three concrete forms this took:

- A probe built with browser-navigation headers (an HTML `Accept`, fetch-metadata headers, an upgrade-insecure-requests header) against a JSON API. An API answering that request may content-negotiate its way to a different response than the one the real client sees.
- A `GET` request still carrying a content type, a content length, and a JSON body left over from a previous tab. A body on a `GET` is malformed, and some proxies route it differently. That is an uncontrolled variable sitting in the middle of an experiment.
- Filtering proxy history for an endpoint name and finding matches, but discovering on inspection that the matches were *page bodies containing the endpoint URL as a string*, not requests to it. That negative was itself the answer: the application never calls that endpoint before authentication, so the whole surface was post-auth and no amount of unauthenticated probing was going to reach it.

**Generalise it:** if you are about to type a request by hand, first ask whether the application can be made to produce it for you.

## Lesson 6: the tooling failure modes that produce silent false negatives

An automated path sweep has several ways to produce a clean-looking column of negatives that mean nothing. All of these were caught before the run rather than after, which is the only time catching them is cheap.

- **Payload URL-encoding is on by default in the popular proxy's fuzzing tool, and its default character set includes the forward slash.** Left enabled, every path payload goes out percent-encoded and every result is a false negative. This is the single most common way a discovery sweep silently produces garbage.
- **Position markers must be inserted by the tool, not typed.** Typing the marker character by hand leaves the position counter at zero, and the tool will run the attack once against a literal marker string. Check the position counter before every run.
- **Matching on a response *header* requires disabling the "exclude HTTP headers" option**, which is on by default. Leave it on and your match column never fires, which reads identically to "no response matched."
- **The length column counts headers, not just the body.** A response with an empty body still measures several hundred bytes, and responses carrying variable-length cookies cluster rather than matching exactly. The read is "outliers from the modal cluster," not "look for zero."
- **Check that every payload actually got tested.** Two entries merged onto one line during a paste, and went out as a single request line containing a space. It returned a plausible-looking 404 that meant nothing, and both paths were still untested.

## Lesson 7: route large responses away from your interactive tools

One probe returned a six-figure-byte HTML error page carrying inline base64 assets. Rendering it locked up the tooling, and the whole diagnostic was contained in the first two lines.

```
curl -sS -o /dev/null -D - -X POST 'https://host/path' \
  -H 'Content-Type: application/json' \
  -H 'X-Research-Header: <handle>' \
  -d '<body>'
```

`-o /dev/null -D -` writes headers to stdout and discards the body entirely. For the cases where you do need the body, save it to a file and grep it locally. Never paste a full response anywhere.

A related time sink worth naming: a large base64 blob inside a page body is almost always a font, an icon, or a sprite. Decoding it costs a round trip and yields nothing. In this case it was a language-selector flag graphic.

## Lesson 8: your tooling is a variable in the experiment

Late in the session the target's main site started returning an error page. The instinct is to reach for one of two explanations, "they are having an outage" or "my IP is blocked," and both are wrong often enough to be dangerous.

The isolating test was one variable on one machine: load the site in a browser with the intercepting proxy **off**, then load it again with the proxy **on**. Same host, same address, same browser, seconds apart. Proxy off worked. Proxy on got the error.

That is the intercepting proxy being flagged, not the network and not the site. The mechanism is worth understanding because it will recur on anything sitting behind modern bot management: **an intercepting proxy terminates and re-originates TLS**, so what reaches the edge is the proxy's TLS and HTTP/2 fingerprint carrying browser-shaped HTTP headers. Headers that say Firefox and a handshake that does not is precisely the mismatch those systems score on. In this case it appeared partway through the day rather than on the first request, which suggests an accumulating behavioural score rather than an instant rejection.

Three consequences, and the third is the one people skip:

1. **It is not a finding.** Bot management catching a proxy is the control functioning as designed.
2. **It changes your working split.** Direct command-line requests for anything repeated or high-volume, the proxy reserved for single crafted requests where its editing and diffing tools actually earn their place. That also keeps proxied volume under whatever threshold you tripped.
3. **Go back and audit which of your existing evidence came through the flagged tool.** This is the uncomfortable part. Findings collected through the proxy during a window when the proxy may have been degraded are not automatically wrong, but they are no longer independently trustworthy, and anything load-bearing should be re-run through the clean tool before you build on it.

In this case the proxy-sourced evidence had a strong self-defence available: it had returned three structurally distinct response signatures, and a blanket block would have flattened all of them into one. That is good reason to believe it was collected cleanly. It is not a substitute for re-running it.

**Generalise it:** when you discover one of your tools was compromised as an observation instrument, the question is not "is this tool working now." It is "which conclusions in my notes depend on data this tool produced, and which of those am I about to build on."

## On being wrong out loud

Two conclusions in this session were stated confidently and were wrong. Both are recorded here because the corrections are more instructive than the conclusions were.

**First**, an HTML response body to an API path was read as "the framework's catch-all served the app shell, there is nothing here." A later header diff proved the opposite: the path was special-cased to an entirely different origin. The error was interpreting a body without having compared the headers.

**Second**, the absence of the upstream-timing header was asserted to prove a request never reached the proxy at all. That is wrong, and it inverts the useful reading. The proxy sets that header only when it forwards to a backend, so a filter-level denial *inside* the proxy produces exactly the same absent-header signature. It is an "a backend answered" oracle, not a "the proxy was reached" oracle.

Both errors share a shape: a single observation, interpreted without a comparison. That is the same failure the entire method above exists to prevent.

## The closing discipline: a documented negative is a result

Three hosts, and the outcome was one closed, one parked, and one deferred behind an account. No bug.

But each of those is a *finished* piece of work rather than an abandoned one. The closed host was proven inert in three requests, with the specific reason recorded. The parked host has a written verdict naming what was tried, what the response signature was, and why further blind guessing has poor expected value. That record is what lets a future session pick up without re-deriving anything, and it is what turns "I didn't find anything" into "I established this is not the surface."

The corollary is knowing when to stop. Twenty-nine informed path guesses against a host returned twenty-nine negatives. The instinct at that point is a longer wordlist. The better move is to change method entirely: passive historical URL sources, or finding the actual client of the API and reading its endpoint list out of the client rather than guessing at it from outside.

If your wordlist is the only thing getting longer, you have stopped doing recon and started doing arithmetic.
