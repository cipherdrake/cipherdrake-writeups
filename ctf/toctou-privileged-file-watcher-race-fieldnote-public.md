---
title: "The Gap Between Validate and Execute: A TOCTOU Race Against a Privileged File-Watcher"
author: CipherDrake
date: "2026-06-12"
category: fieldnote
tags: [appsec, ctf, toctou, race-condition, privilege-escalation, sqli, indirect-rce, linux, methodology]
status: published
sanitized: true (no target identity, platform, hostnames, IPs, usernames, or verbatim error strings)
visibility: public
---

# The Gap Between Validate and Execute: A TOCTOU Race Against a Privileged File-Watcher

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

Two separate bugs did the work on this target, and both share a shape worth naming on its own: something checked a value once, then used a different read of that same value later, and an attacker who could act inside that gap won. One instance was a SQL injection that never touched a query result directly. The other was a full time-of-check-to-time-of-use race against a root-owned automation daemon. This note is mostly about the second, because it is the less commonly written up of the two and the more broadly reusable.

## Indirect RCE: when the injection point and the execution point are different components

The foothold was an unauthenticated, stacked-query SQL injection in a web application's admin API. The obvious move with a stacked query is trying to reach `xp_cmdshell` or an equivalent direct command execution primitive, but this application had none. What it did have was a table the application itself treats as a work queue: rows in a "jobs" or "cron" table that a separate scheduled component picks up and executes on a fixed interval.

`INSERT`ing a row into that table through the injection did not read or write application data directly. It planted a job that a completely different process, running with its own privileges, would pick up and execute on the next cycle, including a job whose "command" was a shell instruction that wrote a web-accessible interpreter script to disk. The injection and the execution never touched the same code path.

The generalizable lead: any application that both accepts a stacked query (or any write primitive into an internal table) and separately executes rows from a jobs/tasks/schedule table is one injection away from code execution, regardless of how well-defended the rest of the application looks. When enumerating a stacked-SQLi target, look specifically for any table whose contents get executed, rendered, or otherwise interpreted by a component other than the one that wrote them. That interpreting component does not need to be vulnerable itself; it only needs to trust its own database.

## The privesc: a root watcher, a lower-privileged owner, and a race

Local enumeration on the box (after generic kernel and sudo escalation paths were checked and closed) surfaced a root-owned file-watcher daemon monitoring a directory the low-privileged foothold account could write to. On a write event, the watcher read the request, mapped it to a "hook" script under a fixed path, applied an input filter to strip dangerous characters from any arguments, and then executed the resolved hook as root.

The filter blocked direct argument injection cleanly; that path was a dead end. The actual gap was structural rather than a filter bypass: the hook scripts themselves were owned by the same lower-privileged account that could trigger the watcher, and there was a window between the moment the daemon resolved which hook file to run and the moment it actually executed that file. That window is the target of a time-of-check-to-time-of-use (TOCTOU) attack. Overwrite the hook file with a malicious script during the window, between resolution and execution, and root runs whatever is on disk at execution time rather than whatever was there at resolution time.

The practical construction: continuously and atomically swap the target hook file between its original, benign contents and a malicious payload (using an atomic rename so the daemon never observes a half-written file, only ever a complete benign version or a complete malicious one) while repeatedly triggering the watcher in a tight loop. Given enough iterations, the daemon's execution lands on an interleaving where the malicious version is on disk at the moment it runs. The payload itself just needs to do something durable and cheap, such as installing a SUID copy of a shell, so a single winning race yields a stable, reusable root primitive rather than a one-shot win that has to be raced again.

## Recognizing the race target

Not every privileged automation surface is racy. The specific structural signature to look for:

- A privileged process (root, a service account, anything more privileged than you) that validates or resolves a file path, then executes that path as a separate step, rather than opening the file once and operating on the open descriptor throughout.
- The file at that path is owned by, or writable by, an account you already control.
- There is any daemon, watcher, or scheduler that lets you trigger the validate-then-execute cycle repeatedly and cheaply (a filesystem event watcher, a cron-adjacent scheduler, a webhook handler).

If all three hold, the file between validation and execution is the race target, and atomic rename is almost always the right swap primitive, because it means the target process only ever sees a complete file, never a torn write that could otherwise crash the daemon and end the attempt early.

## Dead ends worth naming

Before finding the real path, several standard local-privesc checks were run and closed cleanly: a known local-root kernel exploit was patched at the installed package version, a second known sudo-related exploit reported a "vulnerable build" string from an automated suggester but never produced a working session against the actual heap layout present, and a third path required a password that was never recovered. None of those were wasted time; ruling them out with the package manager's own version and changelog, rather than trusting a scanner's heuristic classification, is what freed up the search to find the file-watcher path. A version string that a tool calls "vulnerable" is a candidate to verify against the vendor's actual fix record, not a finding on its own.

One other decoy is worth flagging: a single human-memorable secret sitting among several otherwise machine-generated random secrets in a configuration file. It read as deliberately planted, and it was; it never led anywhere. A secret that stands out by being memorable, next to a set that clearly is not meant to be, is worth one test and then dropping if it fails. It is not a stronger lead than the ACL and process-ownership work still in front of you.

## Portable lessons

- A stacked-query SQLi with no direct command-execution function is not a dead end if the target has any internal table whose rows get executed, scheduled, or rendered by a separate component. Find the interpreter, not the injection sink.
- A privileged watcher (file-system event watcher, cron-adjacent scheduler, webhook handler) that executes files owned by a lower-privileged account is a privesc candidate independent of any kernel or sudo CVE. Check who owns what the privileged process executes, before reaching for named exploits.
- When a handler validates a path and executes it as a separate later step, the file itself is the race target. Atomic rename is the swap primitive of choice because the target process never observes a partially written file.
- A scanner or exploit suggester's "vulnerable build" classification is a candidate to verify against the package manager's actual version and changelog, not a finding. Confirm the patch state directly before investing time in a named exploit.

## Remediation

- Never let a privileged automation account execute a file it does not itself own and control the write permissions on. Hooks or scripts executed by a privileged watcher should be owned by that same privileged account and writable by nothing else.
- Fix validate-then-execute patterns at the code level: open the file once, validate the open descriptor, and execute that descriptor. Re-resolving a path between validation and execution is what creates the race window in the first place.
- Parameterize database queries; the injection that started this chain existed because user input was concatenated directly into SQL.
- Restrict which service accounts can write into directories a privileged scheduler polls, and mount temp/spool directories `noexec`/`nosuid` where the deployment allows it.

## Closing

Neither bug here needed a clever payload so much as a willingness to keep asking "who actually reads this, and when." The SQL injection worked because the database was also a work queue nobody thought of as executable. The privesc worked because a privileged process trusted a filename it had already stopped watching. Both are the same instruction: find the gap between when something is checked and when it is used, and see who can stand in it.
