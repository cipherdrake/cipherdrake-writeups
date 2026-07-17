---
title: "Field Note: Print-Protocol Injection, Path-Traversal, and a Security Feature That Leaks Root"
category: fieldnote
visibility: "public"
tags:
  - fieldnote
  - command-injection
  - path-traversal
  - confused-deputy
  - fd-leak
  - ipc
---

# Field Note: Print-Protocol Injection, Path-Traversal, and a Security Feature That Leaks Root

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

## The shape of it

A three-stage chain built entirely around custom implementations of legacy print protocols. No box name, no platform, no IPs, no real credentials below — the specifics don't matter; the pattern does.

**Stage 1 — job-metadata injection.** A web front end described a legacy print-spooler protocol in its own marketing copy ("queue," "spooler," a named protocol/RFC). That was the tell that a from-scratch implementation of that protocol was reachable somewhere off the obvious port list. Pulling the linked source turned up a custom server that took a job-name field straight out of the protocol's own structured metadata and dropped it, unsanitized, into a shell command built with string interpolation:

```python
subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```

A single quote in the job name broke out of the quoted argument and turned the rest of the string into literal shell syntax. This is not a web-form bug — the injectable field came from a legacy protocol's own metadata, not an HTTP parameter, which is exactly why it's easy to miss when auditing "the web app."

**Stage 2 — path traversal in a hand-rolled filesystem abstraction.** After landing a low-privilege shell (the service account running the print daemon), further enumeration found a second, related service — an emulator for a different print-management protocol — running as a different local user. Black-box probing with the target protocol's real command syntax confirmed the emulator implemented a filesystem command set (list / upload / download a file, addressed by a virtual path). Pulling its own source revealed the path-translation function:

```python
def _translate(self, path):
    clean = path.replace("PREFIX:", "").replace("\\", "/").lstrip("/")
    return os.path.normpath(os.path.join(self._root, clean))
```

String substitution to strip a prefix, then `os.path.normpath(os.path.join(root, clean))`. This looks like sanitization and is not: `normpath` collapses `../` sequences syntactically, but never checks that the *result* is still inside `root`. A path like `PREFIX:\..\.ssh\authorized_keys` sails straight through to a write outside the intended directory. That gave arbitrary file write as the second service's user — used here to plant an SSH key into that user's `authorized_keys` and log in directly.

**Stage 3 — the interesting one: a security feature that leaks the secret it should be protecting.** The newly-reached user could now talk to a local management socket backed by a root-owned daemon. Reading its source showed the real bug: at process startup, before any client had connected or authenticated, the daemon opened a secrets file **as root** and kept the file descriptor alive for the life of the process — no privilege drop anywhere. Its "security lockdown" logic — triggered when it detected signs of the exact filesystem-traversal attack from stage 2 in a log file, a genuine and correct attack signal — responded to the *flagged client itself* by sending an alert bundled with two live file descriptors via `SCM_RIGHTS` Unix-socket ancillary data: the log's fd, and the already-open, root-owned secrets-file fd.

Since Unix permission checks happen at `open()` time, not `read()` time, receiving that already-open descriptor granted full read access to the secrets file regardless of the receiving user's own permissions on it. The daemon's own incident-response mechanism — built to bundle "forensic evidence" for whoever it had just identified as an attacker — handed that attacker a live root-opened handle to the very file it was supposed to be protecting. Reading the descriptor directly recovered an administrative credential, which worked immediately for full privilege escalation.

## Two friction points worth keeping

- **One-shot triggers burn on the wrong client.** The lockdown condition truncated its source log immediately after firing, so it only fired once per log-write. A generic socket probe (one that doesn't know to request `SCM_RIGHTS` ancillary data) still triggers-and-truncates the condition without capturing anything — burning the one shot. The fix needed a purpose-built client using the platform's ancillary-data-receiving API (Python's `socket.recvmsg()` with a properly sized control-message buffer), not a generic netcat-style tool.
- **Single-threaded services wedge on unclosed connections.** A previous raw-socket session against the traversal-vulnerable service had been left open without an explicit close. That service's accept loop was single-threaded — it only accepted a new connection after the current one fully disconnected — so the stale, never-closed session blocked every subsequent connection attempt, including the retry needed to trigger and capture the fd leak. The fix was discipline: close every raw-socket connection explicitly, immediately after each interaction, from then on.

## Key lessons

- A front end that names a legacy protocol in its own copy is a signal to scan past the default port list — custom reimplementations of old protocols tend to land on non-standard ports.
- Any `shell=True`-style command built with string interpolation of external data is injectable, no matter which layer the data comes from — an HTTP parameter, a header, or a field inside a legacy protocol's own structured metadata. Audit every shell-out for interpolation of anything attacker-influenced, not just obvious web inputs.
- String substitution to strip traversal sequences, even when followed by path normalization, is not containment. The only correct check resolves the final path and verifies it is a descendant of the intended root — checking the *output*, not the *input*.
- Any mechanism that passes a live file descriptor to a peer — `SCM_RIGHTS`, a `/proc/<pid>/fd` hardlink, misdirected socket activation — grants the *opener's* permissions, not the receiver's. Any code holding a privileged descriptor open across a client interaction is a confused-deputy risk, independent of whatever checks ran before the descriptor changed hands.
- Security and incident-response tooling is itself attack surface. A feature that automatically bundles "evidence" or diagnostic detail for a flagged client is worth testing for exactly one question: does it hand that client anything it couldn't already read on its own? An alert channel is still a channel.

## Remediation, generalized

- Never build shell commands by interpolating external input; use an argument-list API instead of a shell string, regardless of where the input originates.
- Enforce path containment by resolving the final path and verifying it is a descendant of the intended root before any filesystem operation — never trust that stripping a literal traversal string was sufficient.
- Never pass a live privileged file descriptor to an untrusted peer as part of an alert, evidence, or diagnostic payload. If evidence must be shared, copy the content into a scoped, correctly-permissioned buffer instead of passing the open handle.
- Open privileged resources only inside the specific, already-authenticated code path that needs them — not eagerly at process startup, where the descriptor sits open and reachable for the process's entire lifetime whether or not it's ever legitimately used.
