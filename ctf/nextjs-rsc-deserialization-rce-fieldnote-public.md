---
title: "Two Doors, One Failure: Framework Deserialization RCE and a Debugger Left Open to Root"
author: CipherDrake
date: "2026-06-06"
category: fieldnote
tags: [appsec, ctf, nextjs, deserialization, prototype-pollution, rce, privilege-escalation, exposed-debugger, methodology]
status: published
sanitized: true (no target identity, platform, hostnames, IPs, usernames, or verbatim error strings)
visibility: public
---

# Two Doors, One Failure: Framework Deserialization RCE and a Debugger Left Open to Root

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

A target can look locked down and still hand over root twice, through two doors that have nothing to do with each other on the surface. Both doors here trace back to the same root cause: a component trusted its caller because the caller was already inside the process boundary, and nobody checked whether that boundary actually held. This note covers a framework-level deserialization RCE in a Next.js application (CVE-2025-66478 / CVE-2025-55182), and a root-owned Node.js process left listening on its built-in debugger port. Neither is an application bug. Both are "if you can reach this interface at all, you own the process."

## The tell that pointed at protocol, not routes

The target's entire attack surface was a single Next.js application. Directory brute-forcing and API wordlists returned nothing but true 404s, because a Next.js App Router application only answers the routes it defines, there is no hidden admin page to find. That result matters: when a modern framework's app-directory-based router returns all-404 against a large wordlist, stop hunting for hidden pages. The bug is more likely to live in the framework's own request-handling protocol than in an undiscovered route.

The response headers gave the framework generation away before any exploit was attempted: App Router-specific headers (segment-prefetch and stale-time markers), a leaked build identifier inside the page's inlined payload, and a `Next-Action` request header used by Server Actions. That header is the signal. It means the server will deserialize a client-submitted action payload into live objects on the Node runtime.

## The mechanism: a thenable that walks to the Function constructor

React Server Components reconstruct multipart form fields sent under the `Next-Action` header into JavaScript objects. In the vulnerable version range, the deserializer will treat an object with a `then` property as a promise-like ("thenable") and resolve it. If that `then` value is a specially crafted reference string that walks `__proto__` -> `constructor` -> `constructor`, the deserializer follows the chain straight to `Function`, the JavaScript constructor that turns an arbitrary string into executable code. Handing the deserializer that reference is handing it code execution.

This is a protocol-level vulnerability, not a coding mistake in the target application. Nothing about the app's own logic was wrong; the bug lives in how the framework reconstructs objects from untrusted wire data. Any framework that deserializes attacker-supplied structured input into live object graphs, rather than into inert data, is a candidate for this class: look for a header or field that names an action, function, or handler to be resolved server-side, and test whether the reconstruction walks references you control.

A non-destructive confirmation exists for this bug: a deliberately malformed action payload that would only be accepted by the vulnerable deserializer returns a distinctive server-side digest error rather than a generic parse failure. Getting that distinctive error back is proof the sink is live, without needing to escalate to command execution to confirm it.

## Dead end, tested and closed in two commands

Before finding the real bug, the more famous Next.js middleware-bypass vulnerability (CVE-2025-29927) was the obvious first guess for "Next.js box, must be this." It was tested properly rather than assumed: two full directory sweeps with both known header-repetition payload variants, checking every plausible status code, both came back completely negative. That result eliminated the hypothesis cleanly and forced a pivot to the framework's current CVE landscape, which is where the real bug surfaced. A clean negative on a well-tested hypothesis is progress, not a wasted step. It narrows the search.

## The second door: an exposed runtime debugger

After the foothold, low-privilege credentials pulled from an on-disk data store cracked instantly against a common wordlist (unsalted hashes), which reused cleanly onto the box's remote shell service. From there, process enumeration surfaced a root-owned Node.js process running with its built-in debugger protocol bound and listening.

That is the whole privesc. A runtime debugger port is not read-only. Attaching to it and evaluating an expression executes in that process's context, with that process's privileges. If the process is root, the debugger is root. The only question worth asking about any `--inspect`-style listener, in any language runtime that ships one (Node, Python's debugpy, Java's JDWP, and their peers), is who owns the process behind it. That answer decides whether the port is a curiosity or an instant root.

The listener here was bound to loopback only, which would normally rule it out as external attack surface, but the earlier foothold already put a shell on the box. Loopback-only is not a boundary once an attacker already has a foothold; it only stops the first hop.

## The decoy: a privileged group with no daemon behind it

One more thing was worth ruling out before trusting the debugger path: the low-privilege user belonged to a group that is normally root-equivalent, because its associated service daemon runs as root and group members can drive it to mount the host filesystem inside a privileged container. Every attempt to use it failed with connection errors, and checking the box showed why: the service had never actually finished installing, so the daemon simply did not exist. Group membership that is supposed to be root-equivalent is only as good as the daemon backing it. Verify the daemon or socket exists before spending time on a "privileged group" lead; a plausible-looking misconfiguration can be a total dead end if the thing it's supposed to control was never provisioned.

## Recognition conditions

- Next.js App Router response headers (segment-prefetch, stale-time) plus a `Next-Action` header on POST requests: candidate for RSC deserialization RCE in vulnerable version ranges. Check the framework's current CVEs rather than assuming an older, more famous bug applies.
- Directory/API brute-force on an App Router app returning uniform 404s is a signal to stop route-hunting and look at the framework's request-handling protocol instead.
- Any `--inspect`/`--inspect-brk`-style debug port, in any runtime: resolve the owning process with a process listing before writing it off as low-value just because it is loopback-only.
- A "privileged group" (lxd, docker, and similar) is only as dangerous as the daemon that backs it. Confirm the daemon or socket exists before committing time to that path.

## Portable lessons

- A framework that deserializes untrusted wire data into live objects, rather than plain data, is a prototype-chain-walk candidate. The fix is patching the framework; there is no safe way to keep deserializing untrusted structured input into object graphs.
- Test the well-known CVE first, but test it properly and move on cleanly when it comes back negative. A ruled-out hypothesis is real progress.
- Debug and inspector ports are full code execution in the owning process's context, categorically, regardless of language or framework. Treat any exposed debug protocol as equivalent in severity to an exposed credential.
- Loopback-only bindings are a boundary against remote attackers, not against anyone who already has a foothold on the box.

## Remediation

- Patch the framework to a release outside the vulnerable version window. There is no application-level workaround for a protocol-level deserialization bug; the fix has to happen upstream.
- Never run a production service with its debugger or inspector protocol enabled, and never run that service as a privileged account. If a debugger is genuinely required, bind it to a restricted, authenticated socket and run the underlying service as an unprivileged account.
- Store credentials with a slow, salted key-derivation function, not a fast unsalted hash. A leaked credential store should not equal instant offline cracking.
- Audit group memberships that are conventionally root-equivalent (virtualization/container daemons and similar). Membership without a working daemon is inert, but membership with one is a root grant; treat it that way in access reviews regardless of whether the daemon happens to be running today.

## Closing

Neither bug here required a novel payload once the door was identified; both required recognizing that a component was reachable by an untrusted caller and asking what that caller could do with it. The framework deserializer trusted its own request format; the debugger trusted whoever could reach the port. Recognizing that shape, "reachable equals trusted" rather than "reachable equals authenticated", is the transferable skill, on any stack that ships a deserializer or a debugger.
