---
title: "Field Note: Multipart Parser Differentials and Blind-Exfil Routing on CTF Platforms"
category: field-note
tags: [ctf, web, multipart, file-upload, parser-differential, xss, ctf-methodology]
date: "2026-07-11"
status: "complete"
visibility: "public"
---

# Field Note: Multipart Parser Differentials and Blind-Exfil Routing on CTF Platforms

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

Two portable lessons from a recent CTF web challenge, generalized away from the specific target.

## Lesson one: when two parsers read the same untrusted structure, look for where they disagree

The application in question ran a file-upload feature with an unusual amount of engineering behind a simple check: a reverse-proxy layer ran a hand-rolled, regex-based script to validate uploaded filenames against an extension allowlist (a handful of "safe" extensions like image types), before the request ever reached the application server. The application's own backend framework then parsed the identical multipart request a second time, independently, to actually save the file — and did no validation of its own, trusting that the proxy layer had already checked.

That is the vulnerable shape: **the same attacker-controlled structured input, parsed twice, by two different implementations, for two different purposes.** One parser decides "should this be allowed." The other decides "what actually gets saved and served." When those two parsers disagree about how to interpret the same bytes, the gap between their two answers is the vulnerability.

In this case, the proxy-layer validator was a regex applied against an entire multi-line header block as one string. Its capture group for the filename value was written as a character class, which — unlike the `.` wildcard — is not affected by "does this pattern span multiple lines" settings. That meant an attacker could submit a filename value that was deliberately left unterminated (an opening quote with no matching closing quote) on one header line, followed by an extra, entirely fabricated header line that supplied a closing quote and a "safe"-looking trailing extension. The regex-based parser, reading the whole block as one blob, spanned both lines and picked up the fabricated safe-looking ending — passing the allowlist.

The application's own backend parser, by contrast, was a proper line-structured parser: each header confined strictly to its own physical line. It never saw the fabricated second line as part of the same value. It resolved the filename honestly, from the first (genuinely unterminated, genuinely dangerous) part alone — and saved the file under that real, dangerous extension. The application then served that file back with a Content-Type derived from its actual extension: a legitimate, unescaped rendering surface, no MIME-sniffing tricks needed.

This is structurally identical to HTTP request smuggling — two components disagreeing about where one message ends and another begins — just moved down a layer, from the request-framing boundary to the multipart-body boundary. The recognition call ports cleanly: **any pipeline where a validation layer and a persistence/execution layer each run their own independent parser over the same attacker-controlled structured data is worth testing for a differential**, especially wherever one parser is a "did someone reimplement this by hand" regex-over-a-blob approach and the other is a proper structured parser. Look specifically for values the attacker can leave syntactically unterminated, plus a way to inject additional structure (an extra header line, an extra delimiter) that only one of the two parsers will fold into the "wrong" field.

A secondary, cheaper technique that also defeated the same allowlist (though it did not survive downstream, see below): the validator's extension check only fired when the filename contained a dot at all. A filename with zero dots skipped the check entirely — a reminder that an allowlist implemented as "if there's an extension, check it" is not the same control as "require the extension to be present and safe."

## Lesson two: a downstream execution engine can refuse a bypass that "worked" at the validation layer

The no-dot bypass above genuinely defeated the upload validator, but the payoff still failed — because the response was served with a generic, non-specific Content-Type, and the browser engine that eventually consumed it (in this case, a headless-automation-driven browser, though the same applies to any modern browser doing a direct top-level navigation) refused to render that Content-Type as HTML inline. It treated the response as a download instead, and aborted the navigation rather than executing anything.

That failure mode is worth recognizing on its own: a generic or "unknown" Content-Type is not equivalent to no Content-Type, and modern browser engines are conservative about sniffing an unrecognized type as executable content on a direct, top-level navigation with no user interaction to fall back on. When a bypass technically works upstream but produces a silent abort downstream, the fix is usually not a cleverer payload — it's making the downstream response carry a Content-Type the rendering engine will actually trust, which is exactly what the parser-differential bypass above achieved by forcing a real, dangerous extension to be saved and served honestly.

## Lesson three: on CTF platforms, a target's IP shape tells you whether a private-network exfil destination will work at all

Separately from the vulnerability itself: this class of challenge often needs a delivery mechanism that gets a payload in front of a privileged, automated actor (an admin review bot, a moderation tool) that then executes it and needs to send data back out to an attacker-controlled listener the attacker can actually observe.

CTF platforms that run both persistent "lab" hosts and separately spawned, single-purpose challenge instances often route the two very differently at the network layer. A persistent lab host frequently shares a private VPN-style network with the player, so a payload running inside it can reach back to the player's own VPN-assigned address directly. A freshly spawned, single-purpose challenge instance, on the other hand, may be deployed on general-purpose public infrastructure with no route back into that private network at all — meaning a payload that tries to call back to the player's VPN address will simply never arrive, regardless of firewall rules, because there is no route, not because anything is being blocked.

The practical tell is the shape of the target's own address: a private, lab-range-looking address (the kind reserved for internal VPN or lab networks) suggests the target shares your private network and a direct callback to your own VPN address is the standard move. A plain public-facing address on the target suggests it does not, and a callback needs to go to somewhere both sides can actually reach on the open internet — a publicly hosted request-catching service, or infrastructure the player controls with a real public address — rather than a private VPN peer address.

The corollary lesson: when a blind, out-of-band delivery mechanism goes quiet, check the routing assumption before re-testing the payload itself. A payload that is provably correct (confirmed by testing it manually against the same target through a normal browser session) but that produces nothing when triggered through the automated/blind path is a strong signal to check *where* the callback is trying to go, not to assume the exploit logic is wrong.

## Takeaways

- Two independent parsers over the same untrusted structured input, one for validation and one for persistence/execution, is a vulnerability class worth testing for by default — probe with deliberately unterminated values plus injected extra structure.
- A generic/unrecognized Content-Type is a real control against browser-side execution on direct navigation; a bypass that only gets past the *validator* but not the *renderer* isn't finished — the fix is usually forcing an honest, dangerous Content-Type rather than a sniffing trick.
- On any platform that mixes persistent lab hosts with separately spawned single-purpose instances, check the target's address shape before assuming a private-network callback destination will work — a public-facing target address is a strong signal to use a publicly reachable listener instead.
