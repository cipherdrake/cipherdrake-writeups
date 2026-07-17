---
title: "Field note: the AD object-control chain that ends in AD CS ESC9"
category: "field-note"
tags:
  - active-directory
  - bloodhound
  - acl-abuse
  - writeowner
  - genericwrite
  - genericall
  - shadow-credentials
  - adcs
  - esc9
  - certificate-mapping
visibility: "public"
---

# Field note: the AD object-control chain that ends in AD CS ESC9

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

An assumed-breach pattern that recurs on Active Directory hosts: you start with one low-privileged credential and there is no service to exploit. The whole path is object-control ACLs read off the graph, each edge handing you the next account, terminating in an AD CS certificate abuse that mints a Domain Admin logon. Naming each edge's primitive - and reading the certificate template rather than trusting the auto-scanner - is the skill.

## The shape

A domain controller, valid low-priv creds, WinRM open. The endgame is a credential good enough to log in as Administrator; the middle is a chain of directory permissions.

1. **The graph is the exploit.** Collect BloodHound data, mark your account Owned, and read its **Outbound Object Control** edge by edge, following each target's outbound edges in turn. The *edge type is the technique*:
   - **WriteOwner** on an object = you can become its owner, and an owner can rewrite the DACL.
   - **GenericWrite** on a user = you can write its attributes (Shadow Credentials, or set an SPN for a targeted Kerberoast).
   - **GenericAll** on a user = full control (Shadow Credentials, password reset, UPN rewrite).
   BloodHound *discovers* a multi-hop chain you didn't know existed; CLI tools (bloodyAD `get writable` / `get object --resolve-sd`, a DACL-read module, dacledit) *confirm* a single edge you already suspect. Raw ldapsearch is great for text attributes and membership but the DACL lives in the binary `nTSecurityDescriptor` - it comes back base64-packed and needs the SD-flags control plus a parser, which is exactly what those tools do for you.

2. **WriteOwner on a group is a three-step primitive.** Set yourself as owner; as owner, grant yourself full control by rewriting the DACL; then add yourself as a member. Group membership then *inherits* whatever the group controls - so a WriteOwner on the right group silently gives you the group's GenericWrite/GenericAll over some user.

3. **Write access over a user = that user's credential, via Shadow Credentials.** With GenericWrite/GenericAll you can write the target's `msDS-KeyCredentialLink`, add a key credential, and authenticate via PKINIT to pull the account's NT hash. Prefer this over Kerberoast when the password may not crack - it returns the hash directly, and good tooling restores the attribute afterward. If that account is in a remote-access group, that hash is a shell (and usually the user flag).

4. **The chain steers you to the one account that can abuse AD CS.** The terminal user is typically a "CA operator"-style account with certificate-enrollment rights. That is not a coincidence - the ACL chain exists to hand you the identity that unlocks the certificate abuse.

## ESC9: certificates mapped by UPN, with no SID binding

Enumerate the CA and templates. The auto-scanner's "vulnerable" filter can come up **empty** and the box is still exploitable, because **ESC9 is not a standalone template flaw** - it needs a precondition (write access to an enrollee's UPN) that the ACL chain provides. So read the enabled templates by hand and look for one that is all of:

- **Client Authentication** EKU (the cert can be used to log on),
- **SAN taken from the account's UPN** (name flag "subject alt require UPN"),
- **NoSecurityExtension** enrollment flag (the issued cert omits the SID security extension),
- enrollable by an account you control (the terminal account in the chain).

`NoSecurityExtension` means the certificate has no SID, so the DC maps it to an account **by UPN**. The abuse, and the ordering is load-bearing:

1. With write access over the victim account, set its **UPN to the target** (e.g. `administrator`).
2. **Enroll** in the template as the victim - the issued cert's SAN becomes the target UPN, with no SID.
3. **Restore** the victim's UPN so the target UPN belongs only to the real target account again.
4. **Authenticate** the certificate - the DC, with no SID to bind, maps it by UPN to the real target and returns that account's NT hash.

Pass-the-hash and you are Domain Admin. If you authenticate *before* restoring the UPN, the target UPN is ambiguous and it fails - restore first.

## Recognition calls to keep

- **Assumed-breach AD = read the BloodHound graph; the edge type is the abuse.** WriteOwner/GenericWrite/GenericAll each map to a specific primitive.
- **WriteOwner on a group** = set owner -> rewrite DACL -> add self; membership inherits the group's control.
- **GenericWrite/GenericAll on a user** = its NT hash via Shadow Credentials (`msDS-KeyCredentialLink`), no crack needed.
- **A CA-operator-style terminal account** is the tell that the chain ends in AD CS.
- **An empty "vulnerable templates" scan is not "safe."** Read templates for `NoSecurityExtension` + UPN-based SAN + client-auth enrollable by your account = ESC9, given a UPN-write.
- **ESC9 order:** set target UPN -> enroll -> restore UPN -> auth. The SID-less cert maps by UPN.

## Tooling notes

- Shadow Credentials and the ESC9 request/auth are one toolkit's `shadow`, `req`, `auth` verbs; the ACL edits (set owner / add rights / add member / set UPN) are another's.
- A certificate whose SAN is a bare username (no domain) may need the auth step told the username and domain explicitly to resolve identity.
- Pass-the-hash clients want the NT hash alone, not the `LM:NT` pair.

## Why it matters (defensive)

- Audit and remove non-tier-0 **object-control ACEs** (WriteOwner/GenericWrite/GenericAll) on groups and privileged/service accounts - these are the entire chain.
- Protect and monitor writes to **`msDS-KeyCredentialLink`**; enable strong certificate mapping.
- Remove **NoSecurityExtension** from templates and enforce **StrongCertificateBindingEnforcement (Full)** so certs bind by SID, not UPN - this closes ESC9.
- Least-privilege certificate-template enrollment; treat CA-operator accounts as tier-0.
- Alert on UPN changes to sensitive accounts and on certificate requests whose SAN is a privileged user.

The load-bearing lesson: in AD, a single misplaced object-control permission is not a local issue - it chains, because each primitive grants control of the next account, and modern domains put a certificate authority at the end of that chain where "a certificate is an identity." Fix the ACL hygiene and bind certificates by SID, and the chain never starts.
