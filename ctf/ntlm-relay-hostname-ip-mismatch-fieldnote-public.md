---
title: "Field note: detecting NTLM relay by the hostname/IP mismatch"
category: fieldnote
date: "2026-06-19"
tags:
  - dfir
  - ntlm-relay
  - llmnr-nbtns-poisoning
  - active-directory
  - detection
  - T1557.001
visibility: "public"
---

# Field note: detecting NTLM relay by the hostname/IP mismatch

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

Generalized from a blue-team packet-capture + Windows-event-log investigation. No target, host, account, or platform specifics. Illustrative values only.

## The situation

An alert fires on a suspicious network logon: the **source IP and the source workstation name do not match**. You have a packet capture and the target host's Windows Security log from around the incident. The task is to confirm an attack, attribute it, and prove it.

That single mismatch is the fingerprint of an **NTLM relay** preceded by **name-resolution poisoning** (MITRE T1557.001).

## How the attack reads on the wire and in the log

The chain, reconstructed from two evidence sources:

1. A user on workstation **WS-B** tries to reach a file share. The intended path fails to resolve cleanly (e.g. a broken DFS referral returning `STATUS_NOT_FOUND`), and the client falls back to a broadcast name lookup for a short or mistyped name.
2. A rogue host **R** answers that broadcast with **its own address** - a name it does not own. That is the poisoning.
3. WS-B authenticates to R over the SMB authentication share. R captures the NetNTLM authentication.
4. R **relays** that authentication to a second host **WS-A**, connects to `IPC$`, and drives the Service Control Manager (`OpenSCManagerW` over `svcctl`) for code execution.
5. WS-A logs a network logon (Event ID **4624, Logon Type 3**) whose **Workstation Name = WS-B** (baked into the victim's NTLM blob by the client) but whose **Source Network Address = R**. WS-B's real IP is not R's, so this pair is impossible on a clean network. That is the alert.

## What actually proves each part

**Attribute the attacker by behavior, not by traffic volume.** In a capture, the busiest conversation is often a legitimate server (a DC, a file server). The attacker is the host that **answers name resolution for a name it does not own and returns its own address**. Filter the name-resolution layer (LLMNR / NBT-NS / mDNS) and find the responder that should not be responding.

**The credential is in the authentication message.** The SMB/NTLM authentication (NTLMSSP Type 3 / AUTH) carries the username and the client-supplied host name in readable fields. That host-name field is the same value that becomes the relayed logon's Workstation Name - it is the bridge between the capture and the log.

**The authentication-phase IPC$ is the wildcard form.** During SMB session setup, the implicit IPC$ tree connect uses the wildcard host: `\\*\IPC$`, not `\\<server>\IPC$`. If a question (or a detection) is about the share touched "as part of the authentication process," that wildcard form is the one - distinct from the explicit named `\\host\IPC$` connects that also appear.

**The proof is cross-source correlation.** Neither source alone proves the relay. The capture proves capture-and-relay; the host log proves the logon landed; the few-second pin between the relay exchange and the 4624 proves they are the same event. Normalize both to UTC before pinning (the EVTX `SystemTime` field is already UTC; set the capture tool to UTC explicitly).

## Fields that carry the answer (Windows 4624, Logon Type 3)

- **Source Network Address** vs **Workstation Name** - the mismatch itself.
- **Source Port** - the attacker's ephemeral port; cross-checks against the relay TCP stream in the capture.
- **Logon ID** - the malicious session handle; pivot to session-close / privilege events on it.
- **Logon Type 3** - network logon, consistent with a relay (not a console session).

## Portable recognition rules

- A host answering name resolution for a name it does not own, returning its own address, is the poisoner - regardless of how quietly it talks.
- A LogonType-3 4624 whose Workstation Name resolves to a different IP than its Source Network Address is relayed authentication. Build the detection on that pair.
- The authentication-phase IPC$ is `\\*\IPC$`; the named `\\host\IPC$` connects are something else.
- A failed share/DFS lookup can be the first domino - it pushes the client into the broadcast an attacker poisons. Trace the share access that preceded the broadcast.
- In a multi-evidence investigation, correlation is the proof. Pin the two timelines in UTC.

## Defenses that actually close it

- **Disable LLMNR and NBT-NS** - the chain starts with a broadcast name lookup an attacker can answer. Highest-value single control.
- **Require SMB signing** - it breaks the relay even when poisoning succeeds.
- **Least privilege on remote service control** - the relayed account being able to drive `svcctl` on the target is what made the relay valuable.
- **Alert on the signature directly** - a 4624 (Type 3) whose Workstation Name does not resolve to its Source Network Address, plus any host answering name resolution outside its ownership (rogue-responder detection).
- **Fix broken referrals** - a share path that fails to resolve cleanly trains clients to fall back to poisonable broadcast resolution.
