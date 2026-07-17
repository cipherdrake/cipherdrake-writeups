---
title: "Field note: boundaries enforced in the wrong place"
category: "fieldnote"
visibility: "public"
date: "2026-07-01"
tags:
  - fieldnote
  - web
  - path-traversal
  - credential-reuse
  - privilege-escalation
  - race-condition
---

# Field note: boundaries enforced in the wrong place

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

A full easy-Linux chain, generalized. No target names, addresses, credentials, or flags. The single
thread through every stage: a control existed, but it was enforced in the wrong location. Recognizing
that pattern is what turned each step into the next.

## The chain, by class

1. **Header leak -> hidden virtual host.** A default web server responded with an application-specific
   response header carrying a *hostname* instead of the request IP. That name was a name-based virtual
   host not in public DNS. Adding it to the hosts file and re-requesting served an entirely different
   site.

2. **CMS draft disclosure.** The hidden vhost ran an outdated CMS with a known unauthenticated
   information-disclosure bug: a rendering/preview query parameter returned the content of *unpublished*
   posts with no status check on that code path. A draft contained a "secret" self-registration URL for
   an internal chat system, protected only by the unguessability of the link.

3. **Chatops bot with a file helper.** Self-registering on the chat system exposed a helpdesk bot with
   `list` and `file <path>` commands, documented in a public channel as "restricted to one folder." The
   restriction was built by concatenating user input onto a base path with no canonicalization, so a
   `../` in the filename was a path traversal out of the intended directory.

4. **Config secret reused as a login credential.** Traversal read the bot framework's `.env` config,
   which stored the bot account password in plaintext. The human who set the bot password had reused it
   as their own system SSH password. That single assumption ("the same person set both") converted a
   config read into an interactive shell.

5. **Local privesc via a non-atomic auth check.** The host ran a version of the desktop authorization
   daemon vulnerable to a race-condition auth bypass (a privileged "create admin user" request over the
   system message bus; killing the client mid-authorization makes the check fail open). A public PoC
   created an admin-group user; on this distro that group mapped to sudo, so it escalated to root.

## Recognition calls that port

- A hostname in any HTTP response header that is not the request IP is a vhost to route to. Add it to
  hosts and re-request before concluding a server "just shows a default page."
- "Unpublished" / "draft" / "hidden" is a UI state, not access control. If a rendering flag changes which
  records are returned and no authorization re-check sits on that path, it is a disclosure primitive.
- Any feature that advertises a restricted directory but accepts a filename is a path-traversal candidate.
  Send `../` first. A boundary built from string prefixing rather than path canonicalization is not a
  boundary.
- A recovered service-account secret (bot, DB, API, adapter `.env`) is only as scoped as the assumption
  that it is single-purpose. Try it as a login credential for the human who set it. Service-to-owner
  credential reuse is one of the highest-yield single moves.
- A privileged action gated by an authorization check that is not atomic with the action can fail open
  under a race. Reliability of a timing exploit comes from repetition and tuning the delay, not from a
  different exploit.

## Debugging note

When a public PoC reports success (the account was created) but the follow-on login fails, check the
tool's *own stated default credentials* before theorizing about timing or logic. I burned several
attempts convinced the race window was mis-measured; the actual blocker was using the wrong fork's
default password. Read the help text the tool prints.

## Defensive counterparts

- Strip backend/application-identifying response headers at the proxy.
- Patch the CMS; treat unpublished content as non-public by access control, not by obscurity.
- Canonicalize resolved paths and confirm they stay within the intended root (realpath + prefix check);
  never enforce a directory boundary by string prefix alone.
- Scope, rotate, and never reuse service-account secrets as human login credentials; keep them in a
  secrets manager, not a world-readable-to-the-service `.env`.
- Patch the authorization daemon, restrict which accounts can reach its privileged bus methods, and alert
  on unexpected admin-group user creation.
