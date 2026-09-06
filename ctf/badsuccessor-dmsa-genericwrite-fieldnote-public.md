---
title: "Patched Is Not Dead: BadSuccessor Scoped to Whatever You Can Write"
author: CipherDrake
date: "2026-06-18"
category: fieldnote
tags: [active-directory, ctf, badsuccessor, dmsa, privilege-escalation, acl-abuse, windows, methodology]
status: published
sanitized: true (no target identity, platform, hostnames, IPs, usernames, or verbatim error strings)
visibility: public
---

# Patched Is Not Dead: BadSuccessor Scoped to Whatever You Can Write

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

A patch that closes the headline version of an attack rarely closes the underlying primitive. This target was a Windows Server 2025 domain controller, patched against the well-known form of BadSuccessor, the delegated Managed Service Account (dMSA) migration-abuse technique that lets an attacker with certain OU rights mint a service account that "inherits" the keys of an existing one. The patch made the obvious target, a Domain Admin account, unreachable that way. It did not make the technique dead; it scoped it to any account the attacker already holds a specific write right over. That distinction, patched-but-scoped rather than patched-and-closed, is the whole lesson.

## What BadSuccessor actually needs

A dMSA can be configured to "supersede" an existing account, which is the legitimate migration path for moving a workload from a real service account onto a managed one. The abuse is creating a dMSA under your control, pointing it at a target account, and having the domain controller treat the dMSA as the successor, at which point requesting the dMSA's key material also returns the predecessor account's keys. Before the relevant patch, this worked against essentially any target if the attacker held rights to create a dMSA in some organizational unit, because the DC did not require any prior relationship between the dMSA and its claimed predecessor.

The patch (Windows Server 2025, build 26100.4946) changes the requirement, not the mechanism. Post-patch, the domain controller checks for a bidirectional link, an attribute written on the *target* account itself pointing back at the dMSA, before it will honor the supersede relationship. That attribute is exactly the kind of value that GenericWrite (or GenericAll) over the target account lets you set. So the patch converts "any dMSA-creation right anywhere reaches any account" into "a dMSA-creation right plus a write right on the specific target account reaches that specific account." It closes the technique against accounts you have no write access to, and leaves it fully open against accounts you do.

## Why the obvious target failed and the real one didn't

The natural first move on a Server 2025 domain controller with delegated OU child-creation rights is to try BadSuccessor against Domain Admins directly. It failed here exactly as the patch predicts: without the target-side link, account creation succeeded but the key retrieval step failed outright; forcing the link write without holding rights over the target account failed with an access-control error. Both Domain Admin accounts on the box behaved identically. That is the patched behavior working as intended, and it is worth confirming cleanly rather than assuming BadSuccessor is simply gone, because the negative result here is informative: it means the DC is patched, not that the primitive is unusable.

The actual path opened up later in the engagement, once a foothold with different privileges turned up two edges on a different, lower-tier service account: create-child rights on a dedicated OU set aside for staging delegated MSAs, and a direct write right on the service account itself. That combination is precisely what the patch still allows: a dMSA created in the staging OU, pointed at the service account, with the target-side link written using the write right already held. No Domain Admin rights were needed anywhere in this second attempt, because the write right on the specific target substituted for it entirely.

## The decoy sitting right next to it

The same service account also looked, at first, like a straightforward Kerberoasting target once its Kerberos-encryption-type attribute was downgraded (using the same write right) to force a crackable ticket format. It never cracked, against a large wordlist plus rule sets and several themed lists. That result is itself a signal worth naming: when a service account resists a downgraded, forced-weak-format Kerberoast that should otherwise be trivial, and the same write access that let you force the downgrade also grants you a structural, deterministic takeover path, stop trying to crack it. A password that resists cracking despite every advantage being handed to the attacker is very often deliberately uncrackable bait sitting next to the intended path, not a slow win.

## Recognition conditions

- A Server 2025 domain controller patched to build 26100.4946 or later, where the intended BadSuccessor target fails with an access-control error on the link write, but succeeds on account creation: the DC is patched against the no-write variant specifically, not against the technique generally.
- Any account you hold GenericWrite or GenericAll over, combined with any OU where you can create a child object, is a valid post-patch BadSuccessor target, independent of whether that account is a Domain Admin. The dedicated "MSA staging" OU pattern (or any narrowly-scoped OU meant for service-account lifecycle management) is a strong tell that this exact workflow was anticipated by the environment's designers and not locked down as tightly as the domain admins were.
- A kerberoastable account that resists a forced RC4 downgrade against a strong wordlist, when you already hold write access sufficient for a deterministic takeover, is very likely a decoy. Re-examine the ACLs before sinking more cracking time into it.

## Portable lessons

- "Patched" claims for ACL-abuse-adjacent AD techniques deserve a second question: what precondition did the patch add, and do you already satisfy it through some other right you hold? A patch that adds a target-side check converts a domain-wide primitive into an ACL-scoped one; it does not remove the primitive.
- Any write right over an account (GenericWrite, GenericAll, or a narrower right that includes attribute writes) should be evaluated against every AD abuse primitive whose patched form requires "something on the target," not just against the primitives that were already known to need it before the patch landed.
- When you cannot authenticate directly as the identity holding a useful right, but you have a shell running as that identity, prefer doing the AD writes through the local session's own tooling (a scripting or directory-service interface) rather than assuming the technique is blocked because you lack the identity's plaintext credential or ticket.
- A resistant-to-cracking secret sitting directly next to a deterministic, ACL-backed takeover of the same account is a decoy far more often than a genuine "just needs a bigger wordlist" problem, especially once you already hold the write access needed for the deterministic path.

## Remediation

- Patch domain controllers to a release that enforces the bidirectional target-link requirement, and treat that patch as raising the bar, not closing the door. Follow it with an audit.
- Audit which principals hold write rights (GenericWrite, GenericAll, WriteDACL, WriteOwner) over service accounts, especially any account with elevated group membership or broad delegated access, and treat that write access as equivalent to controlling the account outright, because post-patch BadSuccessor makes that equivalence literal.
- Restrict which organizational units allow delegated MSA (dMSA) creation. A dedicated staging OU for service-account migration is convenient operationally and is exactly the object class this technique needs; scope its create-child rights as tightly as you would scope rights on the accounts it is meant to migrate.
- Do not assume a kerberoastable account with a strong password is safe from the account. If any principal can write to it, credential strength is irrelevant; the ACL is the actual boundary.

## Closing

The lesson under the lesson: a vendor patch closes the specific attack path someone demonstrated, and the underlying primitive usually survives, scoped to whatever precondition the patch decided to check. Before writing off a well-known technique as "patched, not applicable here," ask what the patch actually added as a requirement, and whether some right you already hold happens to satisfy it. On this target, it did.
