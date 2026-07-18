---
title: "Upload-Filename Path Traversal to RCE via Execution-Permission Mismatch — Field Note"
visibility: public
tags:
  - ctf
  - web
  - path-traversal
  - file-upload
  - rce
---

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

# Upload-Filename Path Traversal to RCE via Execution-Permission Mismatch

A field note distilled from a CTF-style web challenge: a file-upload application whose only meaningful vulnerability sat in one place, but which took a long, entirely legitimate recon phase to actually find. The specifics below are generalized to the vulnerability class; no target names, endpoints, or real values are included.

## The setup

A small web app offered a file-upload form with two attacker-influenced name fields: a free-text "name this upload" field, and the filename the browser reports for the file itself. The app also showed a "files on record" panel that looked like it tracked what had been uploaded.

Extensive testing (directory and file brute forcing, parameter guessing, content-negotiation checks, an HTTP method sweep, and automated scanning) established two things before the real bug was found:

- The "files on record" panel was a complete decoy. Every combination of blank/filled fields, empty/real file content, and file type tested produced an identical response. It never reflected upload reality at all. Do not trust an application's own status indicator as evidence of what actually happened server-side — verify independently.
- The application had exactly one reachable route, and its behavior was invariant across a very large test matrix. That total invariance was itself informative: once a broad recon pass is genuinely exhausted and produces uniform non-reaction, the correct move is to stop widening the search and instead push harder on the one input primitive the app actually exposes, rather than continuing to hunt for more surface.

## The vulnerability

The upload's free-text naming field was not cosmetic — it was used server-side to construct an actual file write path. The only defense was a check that counted the number of `../` sequences in that input and rejected anything over a small threshold, responding with an explicit "not allowed to write to this directory" message once the guard actually triggered (the first genuinely input-reactive response seen in the entire test).

That check had two independent gaps:

1. **It counted occurrences, not the resolved path.** A single level of relative traversal stayed under the threshold and was allowed through.
2. **It never validated an absolute path at all.** Supplying a full absolute path as the filename bypassed the relative-traversal logic entirely, because the check was never designed to catch an input that didn't contain the traversal pattern it was looking for.

Lesson: a containment check that pattern-matches the *input string* (counting `../`, blocking certain substrings) is a different — and weaker — control than one that validates the *resolved, canonicalized output path* against the intended directory. Test both axes whenever a traversal guard appears to be counting rather than resolving: a shallow relative traversal that stays under its threshold, and an absolute path that sidesteps the pattern entirely.

## The escalation to RCE

The write path alone wasn't yet code execution. The application's upload directory had script execution disabled — a reasonable, common defensive pattern (allow arbitrary uploads, but stop anything uploaded from running as code in that specific directory). The escalation came from combining the traversal with an executable file extension: writing one directory level above the intended upload location, using a less common but still-executable extension for the server's scripting language, landed the file in a directory that was both reachable over the web *and* still permitted script execution.

The proof that this was genuine code execution (not just a successful write) was that the server returned the *executed output* of the uploaded script, not its raw source — confirming the interpreter had actually run it, not merely served the file back as static content.

Lesson: an execution restriction scoped to one directory does not automatically extend to a directory reached by traversing out of it. Once any server-side file write via traversal is confirmed, check whether the directory it can escape *into* has different execution permissions than the directory it started in — that mismatch, not the traversal by itself, is what turns a write primitive into RCE.

## The decisive recognition

An earlier line of attack (following a challenge-provided hint) had focused on rewriting a server configuration file to disable the upload directory's execution restriction directly — a plausible, hint-aligned technique that produced a confirmed containment guard and one unverified partial result, but nothing conclusive.

The actual breakthrough was a separate, independent test: instead of continuing to guess at configuration-rewrite content or file-system paths, testing whether the *file extension* mattered independently, at a traversal depth already known to bypass the containment check. It did — and that recognition, that extension and traversal depth are two separable variables that each need testing on their own rather than assumed from one confirmed axis, was the load-bearing move of the whole exercise. When a partial result stalls under one technique, isolate and test the other plausible variable directly rather than iterating further on the one already in hand.

## A concrete diagnostic gotcha

Once code execution was live, an early attempt to read a target file returned nothing at all — not even an error. Follow-up diagnostic commands showed that a basic system-info call worked fine, but a file-listing and a file-read call both produced completely empty output, with no visible error either.

The cause: a common code-execution helper function (in this runtime, the analog of a "run a shell command and give me its output" call) only captures standard output, not standard error. A failing command — one pointed at a file that doesn't exist in the current directory — writes its error to standard error, which was silently discarded rather than returned. Redirecting standard error into the captured stream revealed the real error text, which in turn pointed at the correct location (one directory further up) for the file.

Lesson: empty output from a "run a command and return the output" primitive is not proof the command found nothing. Redirect stderr into the captured output before concluding a path or file doesn't exist — silence is equally consistent with a discarded error.

## Recon-methodology notes worth keeping

- **Two flavors of "not found" can exist behind a proxy-plus-backend stack:** one where the request never reaches the actual application (a generic web-server-level response), and one where it reaches the application but matches no route (an application-level response). Both can share the same HTTP status code, so a brute-force scan that filters purely on status code can be blind to the difference. Filter or cross-check by response size/body as well when status-code-only filtering produces a suspiciously uniform "everything is 404" result.
- **A hostname resolving to shared, multi-tenant infrastructure (a load balancer or ingress fronting many targets, not a dedicated host for the one being tested) is a signal to abandon any raw-IP infrastructure scan.** That infrastructure belongs to the platform, not the individual target — scanning it teaches nothing about the actual application and risks probing something out of scope. Resolve and sanity-check what a hostname actually points to before scanning it.

## Why this class matters operationally

Unrestricted file upload leading to remote code execution is one of the most common real-world production misconfigurations — the classic "attacker uploads a web shell" bug family. The two controls that would have prevented this chain, in priority order:

- Validate the fully resolved, canonicalized destination path against the intended directory before writing — not a substring/occurrence count on the raw input.
- Treat script-execution permission as something that must be explicitly and verifiably consistent across every directory reachable from the upload location, not just the immediate upload directory. Do not rely on a single directory-scoped restriction as the only control, and do not rely on filename-extension blocklists — alternate executable extensions for most server-side scripting languages routinely defeat a naive blocklist.
