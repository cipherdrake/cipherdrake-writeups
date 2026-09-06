---
title: "Trusted By Location, Not By Identity: Dev-Tooling RCE and the Hidden-Tools Antipattern"
author: CipherDrake
date: "2026-06-06"
category: fieldnote
tags: [appsec, ctf, rce, privilege-escalation, api-authorization, secrets-management, shadow-api, methodology]
status: published
sanitized: true (no target identity, platform, hostnames, IPs, usernames, or verbatim error strings)
visibility: public
---

# Trusted By Location, Not By Identity: Dev-Tooling RCE and the Hidden-Tools Antipattern

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

Every stage of this target failed the same way: a component assumed that whoever could reach it was already trusted, because in the intended deployment only a trusted caller ever could. Every one of those assumptions was wrong once an attacker had any single foothold. This note walks the pattern across three layers, network-exposed developer tooling, secrets pasted into service unit files, and an internal API that hides part of its own capability surface, because the pattern is the same regardless of which layer you hit first.

## Layer one: developer tooling is RCE by design once it is reachable

The initial foothold was a browser-based inspector tool for a developer protocol (the kind of tool that lets a developer connect to and drive backend integrations locally). Its connect endpoint accepted a client-specified command and argument list and spawned it as a local process, because in its intended use the "client" is the same developer running the tool on their own machine. The service was bound to all interfaces with no authentication in front of that endpoint (CVE-2026-23744 in the affected version range).

The generalizable point: any inspector, debugger, or admin console whose entire purpose is to let a trusted local operator spawn or drive backend processes is unauthenticated RCE the moment it is reachable from outside that operator's own machine. The tool did not have a code execution bug; code execution is the feature. The vulnerability is deployment: binding to every interface instead of loopback, and shipping without a required auth token by default. Before touching any "developer tooling," "internal dashboard," or "debug console" port, assume it is a command-execution primitive and confirm the auth story before anything else.

## Layer two: the process-owner-to-file-owner check

Once inside, the fastest way to find the real privilege boundary was comparing what was listening against who owned it. Two services were bound to loopback only: a notebook/REPL service and an internal operations API. Neither was reachable from outside, but both were reachable from the low-privilege foothold already on the box. A process listing showed the operations API running as a highly privileged account, while its source code on disk was owned by a mid-tier account, not the account running it.

That mismatch is the tell. A process running as a privileged identity, whose code or configuration is writable or even just readable by a less-privileged identity, is a privilege-escalation lead independent of any specific bug in the code. Run a process listing next to a directory listing on every local service you find after a foothold; a privileged process backed by a lower-privileged file owner is worth investigating before anything CVE-specific.

## Layer three: secrets in plaintext service configuration

Reading that privileged service's source required becoming the mid-tier account first, and the path there was almost embarrassingly simple: system unit files are world-readable by default. Grepping the unit-file directory for the loopback services' names and ports surfaced an authentication token pasted directly into a service's startup command. That token authenticated to the notebook/REPL service, and an authenticated session on that kind of service is code execution as whichever account owns it, through its terminal or execution API.

Unit files, container environment blocks, and similar startup configuration are not a safe place to paste a secret just because the process that reads them runs with elevated rights. If anything can read the unit file, the secret is public to that anything. Grep `/etc/systemd` (or its platform equivalent) for tokens, passwords, and keys early in any local enumeration; a secret embedded in a startup command is functionally the same as a secret in a world-readable text file.

## Layer four: the hidden tool table

Becoming the mid-tier account unlocked read access to the privileged operations API's source. That source revealed two things: the API key the service required, and a second table of tool handlers, entirely separate from the one the advertised `/tools/list`-style endpoint actually returned. The advertised API was marketing; the real route map was the handler table in the source. One of the undocumented handlers existed specifically to read arbitrary files out of the privileged account's home directory on request, gated by nothing but the same API key already recovered. Calling it with the right argument returned that account's private key material outright.

This is the most reusable lesson of the whole chain: authorization by "it's not in the documented API" is not authorization. Any service that exposes an introspection or listing endpoint should be assumed to be hiding at least as much as it shows, if the same codebase defines handlers outside that list. When source access is available, always enumerate the full handler/route table in code, not the advertised subset, especially for anything self-describing as internal-only, admin-only, or emergency-only. Those labels usually mean "we didn't build real access control for this," not "this is safe because nobody outside the team knows it exists."

## Reusable checklist

- Any developer/inspector tool whose job is to spawn or drive backend processes on behalf of a local operator is RCE if reachable from outside that operator's machine. Check the auth story before anything else.
- After any foothold, compare `ps`-equivalent output against file ownership for every local service. A privileged process backed by a lower-privileged file owner is a privesc lead regardless of what the code does.
- Grep startup/unit/environment configuration for secrets early. World-readable configuration is a common home for tokens that the developers assumed were private.
- Treat a service's introspection or listing endpoint as a lower bound, not the full picture. If source is available, enumerate every route defined in code, including anything gated by a naming convention (an underscore prefix, "internal," "debug," "admin") rather than real authorization.
- A localhost-only bind and an API key are not "safe once you have any local foothold." Both boundaries assume the caller is already trusted; once you are local, you are the caller they trusted.

## Remediation

- Bind developer, inspector, and debug tooling to loopback only, and require authentication on any endpoint that can spawn a process or execute code, even for "local development" tools. Do not rely on network topology as an authentication control.
- Never run an internal operations service as a highly privileged account when its job is bounded read access. Scope it to a dedicated service account with only the specific reads it needs, and keep that boundary enforced in code, not convention.
- Keep secrets out of unit files, startup command lines, and environment blocks committed to disk in plaintext. Use a secrets-manager integration, a permission-restricted environment file, or the platform's native credential-loading mechanism instead of `--token=`-style flags.
- Remove undocumented "hidden" administrative handlers. If a privileged action exists in the code, it needs real authorization enforced at the handler, not omission from a listing endpoint as its only protection. Treat every handler in the codebase as reachable, because eventually it is.

## Closing

Nothing here required a novel exploit technique. Every step was the same recognition applied at a different layer: something assumed its caller was trusted because of where the caller was standing (on the right network, inside the right process, holding a config file), rather than checking who the caller actually was. Chase that assumption at every service you find after a foothold, and check the code for what the API isn't telling you it can do.
