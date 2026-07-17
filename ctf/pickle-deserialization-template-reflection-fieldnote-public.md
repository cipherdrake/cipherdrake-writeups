---
title: "Field note: unsigned-token deserialization and reflecting output through an existing render path"
category: "web"
vulnerability_class: "Insecure Deserialization (CWE-502)"
date: "2026-07-12"
status: "complete"
tags:
  - ctf
  - web
  - deserialization
  - rce
  - fieldnote
visibility: "public"
---

# Field note: unsigned-token deserialization and reflecting output through an existing render path

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

## The shape of it

A small web application authenticated requests using a token carried in a cookie. The token was built by serializing a user object with a language-native object serializer (the kind of format meant for trusted, same-process data — not a signed session token) and base64-encoding the result. The server side decoded and deserialized that cookie on every request to an authenticated page, *before* checking anything else about it — no signature, no HMAC, nothing tying the value back to a real login. A config value that looked like it was meant to sign something existed elsewhere in the app but was never actually wired to this cookie.

Because the deserializer trusted the byte stream completely, it wasn't just reading data back out — it was willing to reconstruct arbitrary objects, including one whose reconstruction process called an arbitrary function with arbitrary arguments. That is the core of the vulnerability class: a serialization format powerful enough to reconstruct executable behavior, handed a byte string the client fully controls, deserialized with no integrity check first. The result was unauthenticated remote code execution, running as a highly privileged user, on a page that any anonymous request could reach cold — no prior login needed at all.

## Two dead ends before the mechanism worked cleanly

The first two obstacles were not the vulnerability — they were plumbing. A first payload silently failed to execute because it crossed three separate layers of string quoting (the serialized object's own string, the string passed to the code-execution call, and the shell's own command string) and one quote mark broke that chain without raising any visible error. The fix was to stop hand-escaping nested quotes and instead wrap the inner payload as an opaque encoded blob (base64), decoded and executed as a separate step — collapsing three layers of quoting risk into a string with no special characters at all. That is a general-purpose technique worth defaulting to any time a payload has to survive more than one layer of string/shell nesting, independent of the specific vulnerability that got you there.

The second obstacle was environmental: the target container was a minimal Linux base image that simply did not ship a full shell, only a stripped-down one. A shell-specific network redirection trick that depends on a full shell's built-in features couldn't work there regardless of how clean the payload's quoting was. The fix was switching to a reverse shell written in the same language the application itself was running — guaranteed present, since it's the runtime executing the vulnerable code in the first place. The general lesson: don't assume a full-featured shell exists inside a container just because a shell-based technique usually works; check what's actually installed, and prefer a payload written in a language you already know the target can run.

## The real obstacle: no observable side channel

Once the exploit mechanism was proven against a local, self-hosted copy of the same application (built from the target's own published container definition, used purely as a debugging aid), the live target introduced a harder problem: outbound network connections from the target appeared to be blocked entirely. Attempts at an out-of-band callback — a request to an external listener meant only to confirm code execution had happened — got no hits at all, over both encrypted and unencrypted transport, even though the vulnerable request itself was confirmed to have executed (a normal HTTP success response, not an error). Ruling out a certificate problem specifically (since the unencrypted attempt failed identically) pointed to the outbound path being filtered entirely, not a narrower TLS issue. This is common on isolated challenge/sandbox infrastructure: inbound reachability from a tester, but no route out to the general internet.

That closed off the two usual paths — an interactive shell, or an out-of-band callback to prove and extract data — without closing off the vulnerability itself. The fix was to stop looking for a *new* channel and re-read the *existing* one already implicit in the vulnerable code: the deserialized object wasn't just being reconstructed and discarded, it was being handed straight into a page-rendering call that referenced one of the object's attributes in its output. Once that render path was confirmed, the exploitation gadget could be re-pointed away from "run a command" and toward "construct an object whose attribute holds the data I want," using a single-expression, no-shell-required object-construction technique compatible with the deserializer's execution primitive. The reconstructed object's attribute — populated with the sensitive file's contents — rendered directly into the HTTP response body. No shell, no outbound connection, no side channel needed at all.

## Key lessons

- **A serialization format that can reconstruct executable behavior should never deserialize client-controlled input without a signature check first.** If a token, cookie, or cached blob round-trips through a "pickle"-style object serializer (as opposed to a plain data format like JSON), treat the deserialization call itself as the dangerous step — not something to sanitize after the fact.
- **A signing key that exists in configuration but isn't actually wired to the value you're trusting provides zero protection.** Confirm the specific artifact you're relying on for integrity is the one actually being verified, not just that a secret exists somewhere in the app.
- **When a multi-layer injection payload keeps silently failing, suspect the quoting, not the vulnerability.** Wrapping the inner payload as an opaque encoded blob and decoding it as a separate execution step collapses nested-quoting risk regardless of how many string layers are involved.
- **Don't assume a full shell exists inside a container.** Minimal base images frequently ship a stripped-down shell only; a payload written in the target application's own runtime language is a safer default than a shell-specific trick.
- **Confirmed code execution with no working side channel is not a dead end — it's a cue to re-read the vulnerable code path's own data flow.** If the exploited function's return value or output already feeds into something observable (a template render, a log line written back to the client, an existing response field), redirect the exploit to populate that path instead of hunting for a new channel. This generalizes past deserialization: any time you have execution but no shell and no working egress, ask what the vulnerable code already does with its result before assuming you're stuck.
- **A target's inbound-only network posture (reachable from the tester, no outbound route) should be treated as the default assumption for isolated challenge or sandboxed infrastructure**, and verified early with a simple status-code check (did the vulnerable request even succeed) before concluding an exploit failed rather than its side channel.

## Remediation, generalized

- Never deserialize untrusted, client-controlled input with a serialization format capable of reconstructing executable behavior. Use a data-only format (JSON) for anything a client can influence, and if a stateful token is required, use a signed or encrypted token format designed for that purpose.
- If a signature or integrity check exists in the application, verify it is actually applied to every value it's meant to protect — an unused signing key is equivalent to having none.
- Treat any code path that renders a deserialized or otherwise attacker-influenced object's fields into a response as a potential data-exposure channel, not just a display feature — its behavior is only as trustworthy as the object's construction.
- Restrict outbound network access from application/service infrastructure by default (egress filtering) — it happened to close one exploitation path here, and doing it deliberately as a control is good practice generally, not just an accidental obstacle for an attacker.
