---
title: "Field note: the credential-laundering chain on an AD box"
category: "field-note"
tags:
  - active-directory
  - smb
  - guest-access
  - rid-cycling
  - password-spray
  - ldap-description
  - hardcoded-credentials
  - sebackupprivilege
  - pass-the-hash
visibility: "public"
---

# Field note: the credential-laundering chain on an AD box

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

A pattern that recurs on "easy" Active Directory hosts: there is no exploit anywhere in the chain. Every step is a secret stored where a lower-privileged identity can read it, and each read widens the audience for the next secret. The whole box is credentials laundering upward through misplaced trust. Naming the pattern is what makes it fast the next time.

## The shape

A domain controller with no web surface and **SMB signing required**. That single fact reframes the box before you touch anything: a coerced-authentication / NetNTLMv2 **relay** foothold is off the table, so the path is not a captured-hash relay - it is *finding a credential* and walking it up. Recognize signing-required early and drop the relay plan.

From there the chain is four layers of the same failure:

1. **Anonymous/guest read of a non-default share.** Guest is enabled and can READ a share that is not one of the defaults (ADMIN$/C$/IPC$/NETLOGON/SYSVOL). That non-default share is the planted foothold; the defaults are noise. It holds an onboarding/notice file with a **default password but no username**.

2. **A password with no username is not a dead end - it is a prompt to enumerate users.** The same guest/null session can resolve sequential RIDs to account names (RID cycling), producing the domain user list. Spray the password from step 1 across that list; one account never changed the default. The two halves of a credential frequently live in different places on the same host.

3. **A plaintext password in a directory attribute.** Once you have any authenticated bind, dump every user object's **`description`** field. It is a free-text box, so admins type "temp password is..." into it - forgetting that *every authenticated user in the domain can read it*. This hands you a second account for free.

4. **Hardcoded credentials in a script.** That second account can read a *different* non-default share (access control "working" - you simply became the intended identity), which holds a **backup or maintenance script** with a service account's credentials baked into the source in cleartext. Read any `.ps1`/`.bat`/config in a dev or backup share end to end for a `$user`+`$password` pair. That service account is often the one with an interactive-login right.

The interactive-login account gets you a shell and the user flag. Then privesc is one more instance of the same theme:

5. **A backup privilege is read-any-file.** The service account holds **`SeBackupPrivilege`** (or membership in Backup Operators). That is not a minor right - it bypasses file and registry ACLs, so on a DC it reads the credential store: save the SAM and SYSTEM registry hives, pull them offline, and dump. On a domain controller the built-in SAM Administrator **is** the domain Administrator, so the local-hive dump alone yields domain admin - you do not always need the full directory database. Pass-the-hash to a shell.

## Recognition calls to keep

- **SMB signing required** on an AD target = drop the relay plan; the box is a credential chain.
- **Non-default share readable by guest/null** = the planted foothold. Enumerate guest's share view first.
- **A password with no username** = go enumerate users (RID cycle) and spray; do not treat it as incomplete.
- The AD **`description`/`info` free-text attributes are a credential store** - dump them the moment you have any authenticated bind.
- **Scripts hold hardcoded creds** - read every script in a dev/backup share for a plaintext user+password pair.
- **A backup privilege (SeBackup / Backup Operators) is a full-compromise primitive on a DC**, not a minor grant - it reads the hive/credential store directly.
- On a **DC, the SAM built-in Administrator is the domain Administrator** - the local-hive dump can be enough.

## Tooling gotcha

Pass-the-hash tools disagree on hash format: some want the full `LM:NT` pair, others want the **NT hash alone**. If a WinRM PtH client rejects the pair with an "invalid hash format" error, strip the LM half and pass only the NT hash.

## Why it matters (defensive)

Every link is a routine admin habit, and the fix at each is an access decision, not a patch:

- Disable guest on domain controllers; restrict share ACLs to the intended group; never stage default passwords in readable files.
- Never store passwords in directory free-text attributes - audit `description`/`info` for credential-shaped strings.
- Do not hardcode service credentials in scripts; use managed/group-managed service accounts or a secrets vault, and keep scripts out of user-readable shares.
- Enforce change-on-first-logon so leaked default passwords expire before they are useful.
- Treat backup privileges (SeBackupPrivilege / Backup Operators) as Tier-0; grant narrowly and monitor `reg save` of SAM/SYSTEM and access to the directory database.

The load-bearing lesson: the ACLs in this pattern are all technically "working." They are just drawn around the wrong data, for a broader audience than the person who stored the secret imagined.
