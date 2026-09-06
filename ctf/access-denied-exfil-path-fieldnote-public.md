---
title: "Field note: when a privileged remote operation returns access-denied, suspect your output path before your privilege"
author: CipherDrake
category: fieldnote
date: "2026-08-01"
tags:
  - fieldnote
  - public
  - active-directory
  - forest-trust
  - sid-history
  - kerberos
  - methodology
visibility: "public"
---

# Field note: when a privileged remote operation returns access-denied, suspect your output path before your privilege

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

One misdiagnosed error cost several sessions of an otherwise correctly-planned attack chain. The technique was right from the first attempt. The interpretation of a single ambiguous failure was wrong, and it stayed wrong for a long time because the wrong reading felt complete: it had a plausible mechanism, a "control test" that seemed to confirm it, and a fallback plan that felt productive. All three were misleading.

## The setup: a relaxed trust boundary and a privilege-bearing group

Two Active Directory forests, `forest-a.local` and `forest-b.local`, connected by a bidirectional forest trust configured with the trust attribute that treats the far side as external rather than fully internal to the forest hierarchy. That configuration choice has a specific, documented side effect: SID filtering, which normally strips foreign SIDs below a certain RID threshold from crossing the trust, only strips the well-known built-in SIDs (Domain Admins, Enterprise Admins, and similar RID-under-1000 groups). A **custom** group, RID 1000 or above, survives the filter when its SID is carried across in an inter-realm Kerberos ticket.

The target forest had exactly such a group: a custom, oddly-named administrative group with zero real members, nested as a member of the built-in Backup Operators group. Backup Operators carries `SeBackupPrivilege`, which is a full-compromise primitive on a domain controller: it allows a non-administrator to read protected files and, critically, to save registry hives (SAM, SYSTEM, SECURITY) via the remote registry protocol. An empty group nested into Backup Operators, reachable only by injecting its SID, is close to an explicit invitation once you notice the trust is configured to allow it.

**Portable recognition:** if a forest trust is configured to treat the far side as external, check specifically what that trades away, not just that the trust exists. A custom group nested into a high-privilege builtin group on the far side of that kind of trust is a live cross-forest privilege-escalation target, and the configuration itself is the signal that tells you to look for one.

## The forge, and the first ambiguous denial

With domain-admin-equivalent access already established on the near-side forest, forging a golden ticket with the relevant service's key (AES256, since the environment had RC4 disabled) and injecting the custom group's SID as an extra SID produced a ticket that genuinely crossed the trust: it successfully obtained a service ticket against the far-side domain controller. That much worked immediately and was correctly diagnosed as working.

The next step, using that ticket's assumed Backup Operators privilege to save the far-side DC's registry hives to a network share, returned a generic `ACCESS_DENIED` on the underlying RPC call.

That single return code was read as "the injected SID did not survive the trust after all." It is an entirely reasonable first hypothesis, and it is wrong in this specific shape often enough to be worth naming as its own failure mode.

## Why the misdiagnosis persisted

The wrong hypothesis survived multiple rounds of "confirmation" because two supporting observations were themselves misread:

1. A lower-privilege remote-registry operation (a plain read, not a save) succeeded with the same ticket. That was read as "our identity has some access, just not the elevated privilege," which sounds like confirmation that the privilege specifically is missing. It is equally consistent with "our identity has the elevated privilege, and the read operation simply doesn't exercise the code path where the actual problem lives."
2. The identical save operation, run against a different domain controller (one where the identity in question was a genuine local administrator, not relying on cross-forest injection), succeeded. That was treated as a clean control proving the tooling itself was fine, which pushed all remaining suspicion onto the SID. But a same-forest local administrator writing to a share on its own domain and a foreign machine account writing cross-forest to that same share are not the same operation being controlled for. The "control" didn't isolate the variable it was assumed to isolate.

With the injection pronounced dead on that basis, the response was to go looking for an entirely different privilege escalation path on the far-side forest: certificate-services misconfigurations, DNS-write-plus-coercion plans, and so on. Some of that work surfaced real, if ultimately unnecessary, findings (a certificate-template permission scan reported false positives specific to reading permissions cross-forest, which is its own minor lesson: verify a permission-scanning tool's read against an actual write attempt before trusting a bulk "vulnerable" flag, especially across a trust boundary). None of it was needed.

## The actual cause

`ACCESS_DENIED` on a registry-save-style RPC call has (at least) two distinct root causes that produce byte-identical error output:

- The caller genuinely lacks the required privilege (here, `SeBackupPrivilege`).
- The caller has the privilege, but the **destination** for the saved data cannot be written to for an unrelated reason, and the save operation fails at that later stage with the same generic denial rather than a more specific error.

In this case, the save target was a share hosted on a native Windows file server, created for exactly this purpose. A domain controller's machine account, when reaching that share cross-forest as a foreign security principal, was being silently refused the write at the share/filesystem layer, not the privilege layer. Standing up a listener that accepts an SMB write unconditionally (a purpose-built SMB server rather than a native OS file share) resolved it immediately, with the identical ticket, the identical injected SID, and the identical command. The privilege had been present the entire time.

**Portable technique:** before concluding a privilege-escalation primitive is dead because a privileged operation returned `ACCESS_DENIED`, isolate the exfiltration/output path as a separate variable. Point the same operation at a destination you control unconditionally (a listener that accepts writes from anyone, rather than a permissioned native share) before trusting the denial as a verdict on the privilege itself. If the operation succeeds against the permissive destination with the exact same caller identity, the privilege was never the problem.

## A second, related lesson: Kerberos does not survive every tunnel technology equally

Two separate points in this engagement needed genuine cross-realm Kerberos operations (a UDP-dependent DNS lookup against the far-side domain controller early on, and a full inter-realm ticket-enrichment step later). Both failed the first time they were attempted through a SOCKS-style proxy chain, and both failures were, correctly, not attributed to the underlying technique.

A generic SOCKS proxy layered under a Kerberos client can silently break UDP-dependent lookups and can mangle the referral chain a cross-realm ticket depends on, producing failures that look like an authentication or authorization problem rather than a transport problem. Switching the transport to a routed (Layer 3) tunnel, or running the Kerberos-dependent step from a pivot host with native routing to the target realm, removed the failure mode entirely with no change to the technique itself.

**Portable technique:** if a Kerberos operation fails in a way that doesn't match the expected error for the technique being attempted (a transport-shaped failure rather than an auth-shaped one), suspect the tunnel before the ticket. Enrich or validate cross-realm tickets from a host with a direct, native path to the target realm's KDC when one is available, rather than through a generic SOCKS proxy.

## Key lessons

- A relaxed forest-trust configuration (anything that treats the far side as external rather than fully internal) specifically weakens SID filtering for custom, non-built-in group SIDs. Check what a trust configuration trades away, not just that it exists.
- `ACCESS_DENIED` on a privileged remote operation is not a single fact. It conflates "you lack the privilege" and "your privilege is fine but your output destination refused the write," and the two produce identical error text. Isolate the destination as its own variable before condemning the privilege.
- A "control test" only controls for what it actually holds constant. Comparing a same-domain administrator's local write against a foreign machine account's cross-domain write to the same share tests two different operations, not one operation under two conditions.
- Native OS file shares can silently refuse a write from a foreign/cross-trust machine account in ways that produce a generic, unhelpful error at the RPC layer above them. A destination that accepts writes unconditionally is a useful diagnostic tool specifically because it removes that variable, not just a workaround.
- Kerberos through a generic SOCKS proxy chain is unreliable for UDP-dependent lookups and cross-realm referral chains. A routed tunnel, or a pivot host with native routing to the target realm, is the fix, and the failure it fixes is easy to misattribute to the technique under test rather than the transport carrying it.

## Remediation notes

- Audit forest trusts for the external/relaxed-filtering attribute deliberately, not incidentally. If it is set, enumerate every custom group on the far side that is nested into a high-privilege builtin group (Backup Operators, and equivalents), because that nesting is exactly what the relaxed filtering makes reachable.
- Treat Backup Operators membership, direct or via nesting, as equivalent to Domain Admins for auditing purposes, especially across any trust boundary. `SeBackupPrivilege` on a domain controller is a full-compromise primitive, not a convenience grant.
- Restrict which shares a foreign, cross-forest machine account can write to, and alert on registry-save operations targeting an unusual or newly-created destination, regardless of whether the operation itself succeeds or fails.
