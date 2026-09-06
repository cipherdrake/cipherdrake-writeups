---
title: "SSRF Host-Blocklist Parser Differentials, and Why Concealment Isn't Access Control"
author: CipherDrake
category: "web"
tags: [ssrf, blocklist-bypass, parser-differential, ip-encoding, redirect-validation, information-disclosure, obfuscation, methodology]
date: "2026-08-05"
status: "complete"
visibility: "public"
---

# SSRF Host-Blocklist Parser Differentials, and Why Concealment Isn't Access Control

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

## The setup

A web application shipped a "validate a source" feature: paste in a URL, the server fetches it, and the response tells you whether the fetch succeeded, what content type came back, and a preview of the body. Framed as a sanity-check step before some downstream data-import process. Functionally, it is a server-side URL fetcher that hands the caller the fetched status code, content type, and full response body. That is not a blind SSRF. It is a read primitive.

Getting to that feature at all was its own small lesson. The application's front end was a single-page shell whose entire logic lived in one large, obfuscated, encrypted JavaScript bundle: a symmetric key, an IV, and a block of ciphertext, all shipped together in the same file, decrypted in the browser at load time. That is worth naming precisely, because it is a recurring and completely general mistake: **a page that must decrypt itself without any user input necessarily ships everything needed to decrypt it.** The key has to be reachable by the same code that reads the ciphertext. Obfuscating the surrounding code raises the cost of finding the key; it does not remove it. Reading the decrypted plaintext (recovered here by breakpointing the JavaScript execution one step before the decrypted value was consumed, and reading the still-live value out of the debugger) surfaced two things the ~120KB of wrapper existed to hide: an unlinked page with no authentication at all, and the URL-validation API described above. The amount of effort spent concealing something is itself a signal about how much it is worth finding.

## The mechanism: a denylist that checks a string, not an address

The URL-fetch feature rejected obviously dangerous input: non-HTTP(S) schemes were blocked, and a short list of hostnames, `localhost`, `127.0.0.1`, `::1`, and a couple of equivalent literal spellings, were rejected with a distinct "internal or loopback addresses are not permitted" message. Submitting `file://` got a different, distinct "only http and https are supported" message. Two different rejection messages meant two different checks, and that difference became a free classifier: anything that didn't produce either message had passed both checks and reached a real fetch attempt.

The interesting part is what "reached a real fetch" actually meant. Every rejection on the loopback path came back instantly and identically, whether the port tested was one that was certainly closed or one that was certainly open. If the fetch had genuinely been attempted first and validated after, an open port and a closed port could not possibly produce byte-identical timing and content. So the check ran on the URL string, before any socket was opened at all. That is the load-bearing recognition: **the target for a bypass is the parser, not the network.**

A denylist implemented as a literal string or exact-match set comparison only recognizes the spellings it was written with. An operating system's address resolver recognizes many more. Feeding the filter representations of loopback that are not the canonical `127.0.0.1` string produced a completely different outcome: several of them cleared the denylist and then the fetcher's own resolver expanded them straight back to the loopback address anyway.

The representations that worked here: a shortened dotted form (three octets instead of four, e.g. `127.1`, which classic Berkeley-derived address parsers happily expand to `127.0.0.1`), the address as a single 32-bit decimal integer, the same value in hexadecimal, the same value in octal (leading zero, which some parsers still treat as an octal indicator), and the IPv4 address expressed as an IPv4-mapped IPv6 literal. None of those five strings matched a four-or-five-entry literal denylist. All five resolved to the loopback interface once handed to a real socket call. A programmatic hostname/address validation library (the kind that models an address as a structured object rather than comparing raw strings) will typically reject the non-canonical forms as malformed; the OS-level resolver used at actual connection time is far more permissive. That gap between the two is the entire vulnerability.

## The second bypass: validate once, then follow blindly

A completely independent bypass existed alongside the parser differential. The filter validated the URL exactly once, at the moment it was submitted. The actual fetch, however, followed HTTP redirects transparently, with no re-validation of each new location. Standing up a small redirect server on an address the filter did accept, and having it answer with a 302 pointing at the blocked target, produced a full, clean read of content behind the filter. The check the developer wrote was real; it just answered a question ("is this URL allowed") that stopped mattering the moment the response introduced a second URL the check never saw.

Both bypasses share one root cause: the filter is scoped to "the URL as submitted," while the actual attack surface is "every socket the fetcher eventually opens." A single check performed before any DNS resolution or redirect activity can never account for every path from the submitted string to the opened socket.

## Turning the read primitive into a scanner

Because the feature faithfully reported fetch outcomes, the SSRF doubled as an internal port scanner with three distinguishable states: connection-refused (port closed), timeout (filtered, unroutable, or non-responsive), and a full response with status/content-type/body (port open and answering). That third state, applied against the loopback interface once the filter was bypassed, found an internal service bound only to loopback and invisible to any external scan of the host. That service turned out to be an administrative tool whose own login page implied authentication was required, but whose specific detail is outside the scope of this note; the point that generalizes is the scanning technique, not what was found with it.

## Concealment is not access control, twice over

Two separate things on this target relied on nobody finding them rather than on any real control:

- The encrypted client bundle, discussed above: an entire application's routing table hidden behind a decrypt step the browser performs automatically.
- An unguessable subdomain: a specific internal service was reachable only through a randomly-named host, sixteen hex characters with no dictionary word anywhere near it. No wordlist, generic or context-derived, was ever going to produce that string.

The unguessable name did not survive contact with a disclosure endpoint. A configuration/status page, itself gated by an IP allowlist (loopback-only), printed the entire internal routing map, including that "hidden" hostname, in plaintext, once reached. And it was reachable, because the IP allowlist checked the literal address a request originated from, and the SSRF's outbound fetches genuinely originated from the loopback interface on the server's own side. **An IP allowlist stops being an authorization boundary the instant anything inside the perimeter, a proxy, a bot, or a URL-fetching feature, can be made to originate a request on the attacker's behalf.** The allowlist was correctly implemented and completely defeated anyway, because it answered the wrong question: it verified where the request came from, not whether the party that ultimately controlled its content was authorized.

## The baseline-fingerprint discipline

One methodology point recurred three separate times across this engagement, on three unrelated surfaces, and cost real time each time it was skipped: before reading the results of any fuzz, scan, or brute-force run, characterize what the "nothing here" response looks like, on every axis available (status code, byte size, word count, line count), and filter it out before scanning the remaining output. A subdomain-fuzzing pass, a blind SSRF port sweep, and a directory brute force each had their own distinct "absent" fingerprint on this target, and treating raw, unfiltered output as signal, instead of establishing the baseline first, buried the real findings in noise every single time. This is not specific to SSRF or to any one tool; it applies to any enumeration technique that produces a large volume of largely-negative results.

## Portable takeaways

- **Test any host-based SSRF or URL-fetch filter against every alternate representation an OS resolver accepts, not just the canonical spelling.** A literal-string or set-membership denylist that correctly rejects `127.0.0.1` and `localhost` says nothing about a shortened dotted form, a pure decimal or hex or octal encoding, or an IPv4-mapped IPv6 literal. A byte-identical, instant response across every genuinely blocked host, and a different response the moment one alternate encoding actually connects, is how you prove the check runs on the raw string before any connection, rather than on a resolved address after one.
- **A filter that validates once and then follows redirects is a fundamentally weaker control than one that re-validates every hop.** Point any URL-fetch feature at a redirector you control and see whether the second location is checked at all.
- **An IP allowlist is not equivalent to an authorization check.** It verifies request origin, not request intent. Anything inside the perimeter that can be coerced into originating a request, an SSRF, an internal bot, a webhook relay, defeats a loopback-or-internal-only allowlist without needing to spoof anything externally.
- **Treat any obfuscated or encrypted client-side bundle as a target worth decrypting, not an obstacle to route around.** If the page has to decrypt it automatically, the page ships everything needed to decrypt it too. What the obfuscation was spent hiding is usually the highest-value part of the attack surface, precisely because someone thought it was worth hiding.
- **A negative result from a wordlist only disqualifies the wordlist.** An unguessable identifier, a long random token, a randomly-named subdomain, is defeated by finding where the system discloses it (a status page, a config endpoint, an error message, source review), not by more brute force. Downgrading a strong structural signal (like a wildcard certificate covering names you can't yet find) because a dictionary attack came back empty is a mistake worth guarding against explicitly.
- **Establish the negative-result fingerprint (status, size, word count, line count) for any fuzz or scan surface before reading its output**, and re-establish it separately for every distinct surface tested; the "nothing here" signature for one kind of probe does not transfer to another.

## The fix

The general remediation for the parser-differential class: resolve the submitted hostname to an actual IP address before evaluating any allow/deny logic, then check the resolved address's properties directly (private range, loopback, link-local, other reserved ranges) using an address-modeling library rather than string comparison. Re-apply that same resolve-and-check step on every redirect hop the fetch follows, not once at submission. For the disclosure/concealment class: an unauthenticated route, an internal-only endpoint, or a "hidden" identifier all need a real authorization check, not distance from a wordlist or a decrypt step performed client-side. And an IP-based allowlist needs to be paired with hardening against anything in the environment that can proxy a request on an attacker's behalf, since the allowlist alone only ever checks where a request appears to come from.
