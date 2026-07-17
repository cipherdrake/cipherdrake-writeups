---
title: "Field note: string-boundary checks fall to equivalents, and diagnosing a no-op PoC by reading the binary"
category: fieldnote
date: "2026-07-02"
tags:
  - fieldnote
  - public
  - command-injection
  - suid
  - input-filtering
  - methodology
visibility: "public"
---

# Field note: string-boundary checks, and the PoC that "runs" but does nothing

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

Two ideas from one Easy Linux box, both portable.

## 1. A security check on a string representation is not a check on the thing

The foothold and the root on this box were the same bug one layer apart: a defense that asserts something about the *bytes of a string* instead of the *thing the string denotes*.

- A web app stored user-supplied page content that could contain server-side code, and "protected" it by blacklisting the exact lowercase opening tag of the language. The language's parser matches that tag case-insensitively. Uppercasing the tag sailed through the filter and executed. Blacklisting an exact token is defeated by any equivalent representation of it: case, added whitespace, alternate tag forms, encoding.
- A setuid-root helper validated a mount device by checking the path *starts with* an allowed directory prefix, then concatenated that path into a shell command it ran as root without escaping. A device path of the form `/allowed/../elsewhere/;<command>` satisfies the prefix check (it does start with the allowed prefix) while `../` walks back out of the allowed directory and the unescaped `;` injects a second command that runs as root.

Recognition calls that port to other targets:

- When you find an input field that is filtered rather than allowlisted, test *equivalent representations* before believing it is safe. Change case, insert whitespace inside the token, try alternate syntaxes, try encodings. A denylist is a claim about specific bytes, not about behavior.
- A setuid binary that shells out to a system utility with any user-influenced argument is a command-injection candidate. The guard is almost always a string assertion (a prefix, a substring, a "does not contain X") that a metacharacter or a path traversal defeats. Prefix and substring checks do not survive `../` or shell metacharacters.

## 2. When a public exploit's check passes but its trigger does nothing, read the binary

The privilege-escalation PoC for this component is public and well known. Run verbatim, it produced the target binary's own non-zero error code and *no effect*: the injected command never executed. The instinct to re-run it or blame stale state is a trap.

What actually worked:

- **Prove the trigger, not just the setup, with a marker.** Instead of the final payload, inject a command that records who ran it and when (write `id` to a world-readable file). If the marker file never appears, the injection is not reaching a shell at all; the failure is upstream of your payload. This cleanly separates "the vuln did not fire" from "my payload was wrong."
- **The target's own error code is a signal, not noise.** A non-zero exit from the privileged helper (with no side effect) means it bailed at an internal validation before it ever built the dangerous command. That is a different failure from "ran as the wrong user."
- **Read the binary to find the gate.** `strings` on the helper surfaced the checks it enforces: the device-prefix check (which the payload satisfied) and, crucially, the mount-option/format parsing. The stock PoC's short option string was being rejected by that parser before the vulnerable code path was reached.
- **Diff the working variant against the failing one.** A second public PoC used a longer, more complete option string. Swapping only that in pushed the helper past its parser to the vulnerable call, and the marker confirmed execution as root. The load-bearing difference between "no-op" and "root" was the option string, not the injection payload. Only reading the binary made that visible; guessing at the payload never would have.

The general rule: when a known exploit's own precondition check passes but the trigger yields nothing, stop tweaking the payload. Instrument the trigger (marker), read the target's validation logic, and diff the arguments of a variant that is reported to work. The bug is real; something between your input and the vulnerable call is filtering you out, and it is usually visible in the binary.

## Defensive mirror

- Filter dangerous input by allowlist and canonicalization, never by denylisting specific tokens. Normalize first, then validate the normalized form.
- A privileged helper that must shell out should escape every argument or, better, call the underlying syscall/library directly and validate against real objects (an actual device node, an actual allowed mountpoint) rather than a string prefix.
- Do not ship setuid desktop tooling on servers that never run a desktop. Unused privileged binaries are pure attack surface.
