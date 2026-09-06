---
title: "Three Parameters, One Shell Command, One Unvalidated: Validator Asymmetry as an Injection Primitive"
author: CipherDrake
date: "2026-06-28"
category: fieldnote
tags: [appsec, ctf, command-injection, input-validation, api-security, methodology, recognition]
status: published
sanitized: true (no target identity, platform, hostnames, IPs, usernames, or verbatim error strings)
visibility: public
---

# Three Parameters, One Shell Command, One Unvalidated: Validator Asymmetry as an Injection Primitive

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

A validated input feels safe. Whether it actually is depends on whether every input feeding the same downstream sink got the same treatment. On this target, an unauthenticated automation API accepted three arguments for one action, built all three into a single shell command, validated two of them against a strict pattern, and left the third one alone. That asymmetry, not a missing filter, not a novel bypass, was the entire vulnerability. This note is about recognizing that shape and testing for it deliberately, because it is a common real-world pattern and not a CTF contrivance.

## The setup: a local automation API, guest-executable

A local job-runner style dashboard was listening on a loopback port, reachable only from a foothold already on the box. It ran as root and exposed a small set of predefined actions over an HTTP API, with guest execution enabled by default and no authentication required to trigger any of them. Reaching a service like this is not itself the vulnerability; treating "reachable only from localhost" as equivalent to "safe" is what makes services like this valuable once any foothold exists at all. This one had no per-action authorization at all, so its entire threat surface reduced to: what does each action's argument handling actually do.

One action stood out: a "backup a database" style action, taking three arguments corresponding to a database username, database name, and database password, each presumably interpolated into a shell command that invokes the actual backup tool.

## Finding the asymmetry

The natural first move against three arguments feeding one shell command is to try each independently and read the responses carefully. Two of the three arguments, the username and the database name, came back with an explicit, named validation error whenever a shell metacharacter was included: a message stating the value did not match an "ascii identifier" pattern. That is informative on its own. It confirms a validator exists, names its likely shape (an alphanumeric/identifier check), and confirms it applies to those two fields specifically.

The third argument, the password field, produced no such rejection. Testing a command-substitution payload there (`$(...)`) returned no error and no evidence of execution either; that was not immediately conclusive on its own, and the actual break didn't land until testing a quote-breaking payload instead, which did execute. The instructive sequence is testing all three fields as a set, not stopping at the first one that resists you. When a request has multiple parameters that plausibly feed the same sink, and one of them enforces a strict validator, that is a reason to test the others harder, not a reason to conclude the whole request is safe.

## Reading a failed payload as a positive result

The command-substitution attempt against the password field is worth dwelling on, because it looked like a dead end and was actually a clue. No output, no error, no obvious signal either way. But the *absence* of any reaction to `$( )` syntax is itself informative: it means the value is not being evaluated in a context where command substitution is live, most likely because it is already sitting inside a pair of shell quotes. That reframes the next test entirely: instead of trying more substitution variants, the productive next move is a quote-breaking payload, one that closes the existing quote, appends a command, and reopens or comments out the remainder of the line. That payload, on the same field, returned command output directly, confirmed by requesting an identity-check command and seeing a root-level result come back.

A payload that produces no visible effect is not automatically a failed test. If you can reason about *why* it produced nothing, that reasoning often tells you what context you are actually injecting into, and that context tells you what the working payload looks like.

## Why validator asymmetry happens

This is not a hypothetical pattern. It is what partial input hardening looks like in real systems: a developer adds a strict validator to the fields that look most obviously dangerous, typically anything that resembles an identifier or gets used to construct a path or table name, and treats a "password" field as opaque data because passwords are conventionally treated as arbitrary strings elsewhere in the same codebase. That instinct is exactly backwards once the value is interpolated into a shell command instead of passed to a parameterized API; a password field built into a shell string is just as dangerous as any other field, and often less scrutinized because its normal handling elsewhere trains developers to think of it as "just a string, not an identifier."

Whenever multiple parameters feed the same command, query, or interpreter, check whether they are validated as a set or validated individually and inconsistently. A single strict validator applied to some but not all of the parameters reaching the same sink is a strong signal that the remaining parameter is the actual injection point, and it is worth testing before assuming the whole endpoint is hardened because one field rejected you.

## Recognition conditions

- Multiple parameters on one endpoint that plausibly feed the same downstream command, query, or template: test every parameter independently, even after one comes back hardened. A validator on one sibling parameter is evidence about that parameter, not about the others.
- A validation error message that names the check ("must match an identifier pattern," "invalid format," and similar): use it to infer the check's actual shape, and test whether that shape is applied uniformly across every parameter reaching the same sink.
- A payload that produces no visible effect and no error: before discarding it, ask what context would produce exactly that silence. A silent `$( )` attempt against a value that later breaks out via a quote character is evidence the value sits inside existing quotes, not evidence the field is safe.
- "Loopback-only" or "internal-only" service exposure is not a security boundary once any foothold exists on the host. Treat any internal automation API you can reach as fully in scope.

## Portable lessons

- Test siblings, not just the parameter that looks most dangerous. Real hardening is frequently partial, and the field a developer assumed was "just a string" is the one most likely to have been skipped.
- A validation error is free reconnaissance. It tells you the check exists, roughly what it accepts, and by omission, which other parameters might not be checked the same way.
- A payload with no observable effect can still narrow your hypothesis. Reason about what context would explain silence before moving to a different technique at random.
- A command-injection surface delivered through an unconventional field (a filename, a password, a display name) rather than an obvious "command" parameter is common. Anywhere untrusted input reaches string interpolation into a shell, template, or query, evaluate every contributing field, not just the one with the suggestive name.

## Remediation

- Validate every parameter that reaches a shared sink with the same rigor, not just the ones that look identifier-like. If one field in a group needs strict validation, all fields feeding the same downstream interpreter need it.
- Avoid building shell commands from any request-supplied value, full stop. Use an argument-array invocation (no shell interpolation at all) or a dedicated, parameterized library call for the underlying operation instead of string-concatenating a command line.
- Do not expose automation or job-runner dashboards without authentication, even when the intended exposure is loopback-only. A service that will execute arbitrary predefined actions as a privileged account is a high-value target the moment any other foothold exists on the same host.
- Treat "guest execution enabled" as a setting that requires an explicit, documented justification, not a default. Most automation tooling ships this off; verify it stayed off in production configuration.

## Closing

The break here was not a clever payload. It was reading two consistent rejections and one conspicuous silence, and asking what made the third field different. Validator asymmetry across sibling parameters feeding one sink is a recognizable, testable pattern, and it shows up in real production APIs as often as it shows up in a challenge: whenever a validator exists, the next question is always "does it cover everything it needs to," not "does it exist."
