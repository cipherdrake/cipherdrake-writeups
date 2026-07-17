---
title: "Pre-Auth Type Zero: Detecting AS-REP Roasting from the Domain Controller Alone"
date: 2026-06-19
tags: [blueteam, dfir, active-directory, kerberos, asrep-roasting, detection, event-4768, event-4769, attribution, methodology]
status: draft (neutral / voice-agnostic; recast into article voice before publishing)
sanitized: true (no target identity, platform, hostnames, IPs, usernames, account names, SIDs, or paths)
visibility: public
---

# Pre-Auth Type Zero: Detecting AS-REP Roasting from the Domain Controller Alone

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere. No real target, platform, hostnames, IPs, usernames, SIDs, or paths.

AS-REP Roasting is the quieter sibling of Kerberoasting. Both end the same way - an encrypted blob derived from an account's password, cracked offline - but they hit different points in the Kerberos exchange, leave different records, and the field that gives each away is different. This note is the AS-REP version: the one domain-controller event that proves it, the single field that is the signal, and how to name the actor when you have nothing but the DC log to work with.

## What AS-REP Roasting actually is

Normal Kerberos makes a client prove it knows its password before the KDC issues anything. The client encrypts a timestamp with its password-derived key and sends it in the initial request; the KDC decrypts it to confirm identity. This step is **pre-authentication**.

Some accounts have pre-authentication turned off - the "do not require Kerberos pre-authentication" setting. Usually it is a legacy account, an old service account, or something nobody has audited in years. For any such account, anyone can send an initial ticket request **without credentials at all**, and the KDC will return an AS-REP whose encrypted portion is derived from that account's password hash. The attacker captures that blob and brute-forces it offline. No password needed to ask, no failed logon, no lockout.

The precondition is the whole game: the attack only works against accounts that have pre-auth disabled. That single fact is also what makes it detectable, because "pre-auth was not performed" is recorded explicitly.

## The DC signal: Event 4768 and the pre-auth-type field

This is the first place people go wrong, because the muscle memory from Kerberoasting points at the wrong event. Kerberoasting is the *service*-ticket request, logged as Event 4769. AS-REP Roasting is the *initial*-ticket request - the TGT - logged as **Event ID 4768** ("a Kerberos authentication ticket (TGT) was requested"). Wrong event, wrong investigation. The first triage question for any roast is: TGT (4768) or TGS (4769)?

On the 4768, the load-bearing field is **Pre-Authentication Type**.

- Type `2` is the normal flow: the client pre-authenticated with an encrypted timestamp before the KDC issued the ticket.
- Type `0` means no pre-authentication was performed - which is only possible when the account has pre-auth disabled. That is the exact precondition AS-REP Roasting requires.

So you do not alert on 4768; it is routine. You alert on **4768 with pre-auth type 0**. In a normally configured domain almost nothing legitimately produces it, which makes it high-fidelity on its own.

```
# across all TGT requests, the pre-auth type is the lead
4768 events:
  PreAuth type 2  ......  routine    <- normal, pre-authenticated
  PreAuth type 0  ......  the lead   <- no pre-auth = roastable account
```

There is a corroborating field, the same one that betrays Kerberoasting: **Ticket Encryption Type**. Roasting tooling tends to request RC4 (`0x17`) rather than AES (`0x12`) because the RC4 format cracks far faster offline. A type-0 pre-auth and an RC4 encryption type on the same 4768 is about as clean as an AD detection gets.

From that one event you also read:

- the **target account name** - the account that got roasted (the one with pre-auth disabled),
- the **account SID** - same record,
- the **source address** - the host the request came from, your pivot.

One field note on the source address: on dual-stack hosts it is often logged as an **IPv4-mapped IPv6 address**, written `::ffff:` followed by the real IPv4 address. The address is the tail; the `::ffff:` is a wrapper. Loopback (`::1`) on these events is just the DC talking to itself - normal.

## The attribution trap: the roast event has no actor

Here is the part specific to AS-REP Roasting, and it is the question most likely to be asked: who *ran* it?

The 4768 names the **target** account and the **source host**, but it does **not** name the actor. Because the request for a pre-auth-disabled account is sent without credentials, the event has no authenticated subject - there is no requesting-user field to read. The single most common error is to report the *targeted* account as the attacker. The target is the victim of the roast, not the operator.

When you also have the source workstation's own artifacts, attribution is straightforward host triage. But often you do not - the source machine has not been collected yet, and all you hold is the DC log. You can still attribute, because the DC logs other things that *do* carry the requesting user and the client address:

- **Service-ticket requests (Event 4769)** carry the requesting account and the source address.
- **Network-share access (Event 5140)** carries the accessing account and the source address.

Pivot on the source address from the roast, and list every event referencing it. The authenticated domain user operating from that same host - the one whose 4769s and 5140s appear around the time of the roast - is your actor. That is the account to contain. Note that a logon event (the usual first stop) may be entirely absent from a given export; 4769 and 5140 are underrated attribution sources precisely because they survive when logon records do not.

```
source-address pivot, DC log only:
  4768  target=<roasted account>          (the roast, no requester)   <- victim
  4769  requester=<actor account>          from same source           \
  5140  subject=<actor account>            from same source            > the operator
  5140  subject=<actor account>            from same source           /
```

## The timeline

```
T+0s     DC 4768: TGT requested, pre-auth type 0, RC4, target = roasted account, from host X
T+~70s   DC 4769: service ticket requested by actor account, from host X
T+~70s   DC 5140: actor account accesses a share, from host X
```

The roast is the unauthenticated event with no operator; the authenticated activity from the same host, seconds to a couple of minutes later, is the operator. The source address is the only thread tying the anonymous roast to a named account. Confirming the finding here is not one smoking-gun line - it is the roast plus the same-host attribution stitched together.

## Defensive controls, in order of leverage

- **Clear "do not require Kerberos pre-authentication" everywhere.** This setting is the sole precondition; remove it and the attack is impossible. Sweep stale and legacy accounts specifically - they are where it hides.
- **Disable and clean up dormant privileged accounts.** An unused old account that still authenticates is both bait and symptom. A disabled account cannot be roasted.
- **Enforce AES and reject RC4** so the downgrade is unavailable, and set **long, random, managed passwords** on any account that genuinely must keep pre-auth disabled, so an offline crack is infeasible even if an AS-REP leaks.
- **Write the detection rule:** Event 4768 with pre-auth type `0`, weighted higher from a non-loopback source address and higher still when paired with RC4. It fires on the request itself, before any cracking happens.
- **Forward DC Security logs to a SIEM** so attribution-by-source-address survives a local log roll, and so 4768 / 4769 / 5140 can be correlated centrally when source-host triage is delayed or unavailable.

## Reusable checklist

- For any suspected roast, first ask **TGT (4768) or TGS (4769)?** AS-REP Roasting is 4768; Kerberoasting is 4769. The answer routes the whole investigation.
- On 4768, do not alert on the event - alert on **pre-auth type 0**. Treat RC4 (`0x17`) on the same record as corroboration.
- From the anomalous 4768, read target account, SID, and source address. Strip any `::ffff:` IPv4-mapped wrapper; ignore `::1` loopback.
- Do **not** report the targeted account as the attacker. The 4768 has no requester by design.
- Attribute the actor by pivoting on the source address: the authenticated user in nearby 4769 / 5140 events from the same host is the operator - even with no source-machine artifacts and no logon event.
- Build the timeline: the anonymous roast plus same-host authenticated activity is the proof.

## Closing

AS-REP Roasting reduces to one field most of the time: a TGT request where pre-authentication was never performed. The account that shows up is the victim, not the villain - the villain is whoever was authenticated on the same workstation, which the domain controller can tell you even when the workstation itself is out of reach. The portable lesson is to match the event to the attack (4768, not 4769), read the one field that encodes the precondition, and never mistake the roasted account for the actor. The domain controller alone is often enough.
