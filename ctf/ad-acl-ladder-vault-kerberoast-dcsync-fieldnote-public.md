---
title: "Field note: ACL ladder + a credential vault + GenericWrite->Kerberoast->DCSync"
category: "field-note"
tags:
  - active-directory
  - bloodhound
  - acl-abuse
  - forcechangepassword
  - password-safe
  - genericwrite
  - shadow-credentials
  - targeted-kerberoast
  - dcsync
  - pkinit
visibility: "public"
---

# Field note: ACL ladder + a credential vault + GenericWrite -> Kerberoast -> DCSync

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

An assumed-breach AD pattern that mixes three moves: a ladder of object-control ACL edges, an **off-graph** pivot through a credential file, and a final GenericWrite that turns into DCSync. No service exploit anywhere. Two lessons stand out - "when the graph dead-ends, look at what the account can *reach*," and "read the error, don't assume the technique."

## The shape

A domain controller, one low-priv credential, WinRM open, and one **unusual service** (here FTP) that does not belong on a DC. The unusual service is a flag: it usually stores files - backups, exports, a secrets vault - that a low-priv account can read.

1. **Walk the ACL ladder off the BloodHound graph.** Mark your account Owned, read outbound object control, and follow each target's outbound edge. The edge type is the abuse:
   - **GenericAll / WriteOwner+WriteDacl** over a user = full control (reset its password without the old one).
   - **ForceChangePassword** over a user = reset its password.
   Chain the resets down the ladder (A resets B, then as B reset C).

2. **When a node's outbound object control is 0, the chain continues off-graph.** That account is not a dead end - its *value is access*, not another edge. Look at what it can reach: a share, the odd service (FTP), a credential vault, a config with secrets. This is the pivot the graph can't draw.

3. **A password-manager file is an offline crack, then a credential multiplier.** Pull a `.psafe3` (Password Safe) or `.kdbx` (KeePass) off that access and crack the master password offline (`pwsafe2john`/`keepass2john` -> John/hashcat, wordlist). The vault's stored entries are *other users'* credentials - one of them is usually WinRM-capable (a shell and the user flag) and holds a further AD position. The vault did not just hand you a login; it handed you an account with a graph edge.

4. **The recovered account's GenericWrite -> DCSync is the finish.** That user often has **GenericWrite** over another account that holds **DCSync** rights on the domain (the three replication edges: GetChanges + GetChangesAll + GetChangesInFilteredSet). You cannot DCSync as the GenericWrite holder directly; you go through the DCSync-holder.

## GenericWrite has two abuses - pick by what the DC supports

GenericWrite over a user gives you two ways to seize it, and the box decides which works:

- **Shadow Credentials** - write `msDS-KeyCredentialLink`, then authenticate via **PKINIT** to pull the NT hash. Clean and non-destructive - **but it needs PKINIT**, which needs the DC to have a KDC certificate (i.e. AD CS present). On a DC with no AD CS, the *write* succeeds but the *auth* fails with **`KDC_ERR_PADATA_TYPE_NOSUPP`**. That error is the definitive "this DC can't do PKINIT" signal - stop trying Shadow Credentials.
- **Targeted Kerberoast** - write an **SPN** onto the user, request its **RC4 TGS**, crack it offline. No PKINIT, no AD CS - just an SPN and a service ticket. This is the pivot when Shadow Credentials dead-ends. "Targeted" because the account is not normally a service account; you make it roastable on demand.

Then, as the cracked/owned DCSync-holder:

- **DCSync** the domain (`secretsdump -just-dc-user Administrator`) for the Administrator NT hash, and **pass-the-hash** over WinRM.

## Recognition calls to keep

- **An unusual service on a DC (FTP, etc.) = a file/credential store** a low-priv account can probably read.
- **BloodHound node with outbound control 0 = go off-graph** - what can that identity *reach*?
- **GenericAll/ForceChangePassword = password reset** without the old password; chain down the ladder.
- **A password vault is a credential multiplier** - crack the master offline, the entries continue the chain.
- **GenericWrite = Shadow Credentials OR targeted Kerberoast** - `KDC_ERR_PADATA_TYPE_NOSUPP` on the shadow-auth means no PKINIT, so roast instead.
- **DCSync = GetChanges + GetChangesAll**; own the holder (roast/shadow), then dump.
- **Read the error, don't assume the technique** - the reflexive GenericWrite move (Shadow Credentials) can be structurally impossible on a given DC.

## Tooling notes

- `*2john` tools (`pwsafe2john`, `keepass2john`) emit John's `user:hash` format; hashcat wants the bare hash (strip the `user:` prefix and the trailing newline). Easiest to just use John.
- Jumbo John's binary can live in `/usr/sbin` (off a normal user PATH).
- No `ftp` client? `curl ftp://host/` lists (trailing slash), `curl ftp://host/file -O` downloads.
- Some cert-auth tools expect an unprotected PFX; strip a password-protected one with `openssl pkcs12 -nodes` and re-export with an empty password.
- Kerberoast crack mode: John `krb5tgs` / hashcat `-m 13100`.

## Why it matters (defensive)

- Audit/remove non-tier-0 object-control ACEs (GenericAll/GenericWrite/ForceChangePassword) - the whole ladder is leftover delegation.
- Don't run FTP (or other file services) on a DC, and never store credential vaults/backups where a low-priv user can read them; the master password must be strong (this one was in a common wordlist).
- Protect `msDS-KeyCredentialLink` and `servicePrincipalName` writes; alert on SPNs added to normal user accounts and on RC4 TGS requests.
- Enforce AES / disable RC4 so kerberoast hashes are impractical.
- Restrict DCSync (directory-replication) rights to DCs only; alert on GetNCChanges from non-DC principals.

The load-bearing lessons: in AD, a chain can leave the graph (an account's value is what it can *reach*), a password vault turns one credential into several, and a single primitive like GenericWrite has more than one abuse - so read what the DC actually supports (the PKINIT error) instead of forcing the reflexive technique.
