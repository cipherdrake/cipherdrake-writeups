---
title: "One Typo, One Weak Password: Reading an LLMNR Poisoning Attack Out of a Packet Capture"
date: 2026-06-19
tags: [blueteam, dfir, network-forensics, active-directory, llmnr, nbt-ns, responder, ntlmv2, netntlmv2, pcap, wireshark, methodology]
status: draft (neutral / voice-agnostic; recast into article voice before publishing)
sanitized: true (no target identity, platform, hostnames, IPs, usernames, share names, passwords, challenge values, or paths)
visibility: public
---

# One Typo, One Weak Password: Reading an LLMNR Poisoning Attack Out of a Packet Capture

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere. No real target, platform, hostnames, IPs, usernames, share names, passwords, or challenge values.

LLMNR poisoning is one of the cheapest credential thefts on a Windows network, and from a packet capture it reads as a clean little story: a user mistypes a hostname, name resolution falls back to a broadcast, a rogue machine answers "that is me," and the victim hands over an authentication that cracks offline. The whole thing turns on two recognitions: how to spot the poisoner among look-alike addresses, and how to stitch a crackable hash back together out of the negotiation fields. This is that workflow, protocol layer by protocol layer.

## What the attack actually is

When a Windows host needs to resolve a name and DNS has no answer, it falls back to Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS): it shouts the name onto the local segment and trusts whoever answers. A poisoning tool sits on that segment and answers every one of those broadcasts, claiming the requested name maps to the attacker's address. The victim then connects to the attacker and tries to authenticate, leaking a NetNTLMv2 response. Nothing is exploited in the classic sense. The protocol is doing exactly what it was designed to do; the design just trusts the loudest answer.

The usual trigger is mundane: a typo. A user means to reach a real host, fat-fingers the name, DNS has no record for the misspelling, and the bad name is what gets broadcast and answered. In the capture, the misspelled name sitting in the broadcast query is both the root cause and a finding in its own right.

## Finding the poisoner: behavior, not address

The first instinct is to look for an out-of-place IP. That instinct fails here, because the poisoner usually sits in the **same subnet as its victims**, often an address or two away. You cannot pick it out by range. You pick it out by behavior.

Filter the capture to the name-resolution protocol and read the Info column. You will see two kinds of rows: queries (a host asking "who is NAME?") and responses (something answering). The rule that resolves it:

- A legitimate host answers a name-resolution query only for **its own** name.
- The poisoner answers for **arbitrary** names it does not own, handing back its own address every time.

So the attacker is the **Source of the response rows**, and the giveaway is that the same address answers for many different requested names. Read the responder, not the requester.

One trap to avoid: do not grab a multicast group address as if it were the attacker. LLMNR and mDNS use fixed group addresses (an IPv4 `224.0.0.x` address and an IPv6 `ff02::` address) as the **destination** of queries. Anything in the destination column of a query that starts `ff02::` or `224.0.0.` is a group, never a host. The attacker is a real source address on the response side.

## Pinning the rogue's real identity: it lies everywhere but its lease

Once you have the poisoner's address, naming the box is the next question, and this is where a careless analyst submits a wrong answer with confidence. A poisoning tool fabricates identities across every name protocol it touches:

- It presents a **spoofed server name** in the SMB/NTLM challenge metadata.
- It impersonates other workstations in **mDNS** and **NBT-NS** responses.

Every one of those is a claimed identity, planted to look convincing. None of them is reliably the box's real hostname.

The honest source is the rogue's **own network configuration**. When the box joined the network it requested a lease, and a DHCP request carries the client's self-declared hostname (the DHCP "Host Name" option). That is the machine naming itself for its own purposes, not projecting a name at a victim. Two cautions make this reliable:

- Tie the DHCP packet to the attacker's address through the **request/acknowledgement pair**, because a broad address filter will also catch other hosts' DHCP traffic that merely involved that address during lease churn. The lease the attacker actually takes is the one whose hostname counts.
- A hostname that does not match the asset inventory (a pentest-distro default name on a corporate VLAN, say) is itself a high-fidelity rogue-device signal.

The portable recognition: **a poisoning box lies in every name-resolution protocol and tells the truth in its own DHCP lease.**

## Reconstructing the credential from the negotiation

The captured authentication is a NetNTLMv2 response, and it is crackable offline if you reassemble it correctly from the handshake. The handshake has three messages, always in order:

- **Negotiate** (type 1): the client opening the conversation. Carries neither value you need.
- **Challenge** (type 2): the server (here the attacker) replying. Carries the **server challenge**.
- **Authenticate** (type 3): the client answering. Carries the **NTProofStr**, the rest of the NTLMv2 response, and the **username and domain**.

Two things trip people here. First, the server challenge and the NTProofStr live in **different messages**, and they must come from the **same** exchange or the reassembled hash will not crack. Second, the host name recorded in the authenticate message is the **victim's own** workstation identifying itself, not the attacker; read the username and domain from that message, but do not mistake the client host for the rogue.

The reassembly format for the standard NetNTLMv2 cracking mode is:

```
username::domain:serverchallenge:NTProofStr:blob
```

where `blob` is the **full NTLMv2 response minus its first 16 bytes**. Those first 16 bytes are the NTProofStr, which already occupies its own field. Including it twice is the classic "line-length" failure. Copy each field by value from the dissector rather than retyping it, assemble the line, and run it through a wordlist:

```
# illustrative only; values are placeholders
USER::DOMAIN:<16-byte server challenge>:<16-byte NTProofStr>:<rest-of-NTLMv2-response>
# then: standard NetNTLMv2 mode against a common wordlist
```

If the password is in a common wordlist, it falls in seconds. That speed is not a footnote; it is the finding. The gap between "a hash was captured" and "the account is compromised" is exactly how weak the password is, and a value sitting in a public wordlist closes that gap instantly.

## The timeline closes the loop

After the leak, the victim typically reaches the **correctly spelled** host on a later connection. Pulling that connection's share/resource path out of the capture recovers what the user actually meant to reach, and contrasting it with the misspelled name from the poisoned broadcast tells the whole story in two strings: the intended target, and the one-character typo that redirected the authentication to an attacker.

## Defensive controls, in order of leverage

- **Disable LLMNR and NBT-NS** by policy. With both off, a failed name lookup fails cleanly instead of broadcasting a poisonable request. This single control removes the entire attack class, and it is the highest-leverage change available.
- **Require SMB signing** (require, not merely enable) so a captured or relayed authentication cannot be replayed against another host. Poisoning can still capture a hash for offline cracking, but relay is shut down.
- **Enforce long, random, managed passwords** so an offline NetNTLMv2 crack is infeasible even when a hash leaks.
- **Watch the segment for rogue responders.** An alert for any host answering name-resolution queries for many distinct names (or any host newly answering at all) catches a poisoning tool the moment it starts.
- **Alert on DHCP hostnames that do not match the asset inventory.** A foreign or default-distro hostname on a managed VLAN is a free rogue-device signal.

## Reusable checklist

- Filter to the name-resolution protocol; separate query rows from response rows by the Info column before trusting any address.
- The poisoner is the **source of the responses**, answering for names it does not own. Ignore multicast group destinations (`ff02::`, `224.0.0.`); they are not hosts.
- For the rogue's real hostname, read the **DHCP host-name option on its own lease**, matched to its address via the request/ack pair. Treat every name it presents in LLMNR/mDNS/NBT-NS/SMB as a claimed identity, not a fact.
- Read the username and domain from the **authenticate** message, but do not confuse the client host name there with the attacker.
- Pull the server challenge from the **challenge** message and the NTProofStr from the **authenticate** message of the **same** exchange.
- Reassemble as `username::domain:serverchallenge:NTProofStr:blob`, with `blob` = NTLMv2 response minus its first 16 bytes. Do not repeat the NTProofStr.
- Record the **time to crack** as the risk statement, not just the recovered password.
- Recover the correctly spelled target from a later connection and contrast it with the typo to tell the full story.

## Closing

The break is recognition, not tooling: a host answering for names it has no business owning, a real hostname hiding in a DHCP lease while fake ones are paraded everywhere else, and a crackable authentication split across two negotiation messages that only count when paired. The lesson that ports to every network-forensics case of this class is that name resolution trusts the loudest answer, and the attacker's whole job is to be loud. One typo plus one weak password is all it takes, and the only honest signal on the wire is the difference between a host naming itself and a host naming everyone else.
