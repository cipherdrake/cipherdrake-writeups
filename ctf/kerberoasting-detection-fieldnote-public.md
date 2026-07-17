---
title: "One RC4 Ticket in a Field of AES: Detecting Kerberoasting Across the DC and the Endpoint"
date: 2026-06-19
tags: [blueteam, dfir, active-directory, kerberos, kerberoasting, detection, event-4769, powershell-logging, prefetch, methodology]
status: draft (neutral / voice-agnostic; recast into article voice before publishing)
sanitized: true (no target identity, platform, hostnames, IPs, usernames, account names, or paths)
visibility: public
---

# One RC4 Ticket in a Field of AES: Detecting Kerberoasting Across the DC and the Endpoint

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere. No real target, platform, hostnames, IPs, usernames, or paths.

Kerberoasting is loud if you know which field to read, and silent if you do not. The whole attack leaves one high-fidelity record on the domain controller and two corroborating records on the endpoint, and the skill is correlating them into a single timeline. No one artifact proves it; the three together are airtight. This is the detection pattern, the field that gives it away, and why a single source is never enough.

## What Kerberoasting actually is

An authenticated user asks the KDC for a service ticket (a TGS) for any account that has a Service Principal Name. The KDC mints that ticket encrypted with the **service account's own password hash**, and it does not check whether the requester is allowed to use the service. The attacker captures the encrypted ticket and brute-forces the password offline, trying candidates until one decrypts the ticket cleanly. Nothing else touches the domain controller. No failed logons, no lockouts. The crack happens on the attacker's machine where your logs will never see it.

That design is why the only on-DC fingerprint is the ticket request itself, and why detection lives or dies on reading that one event correctly.

## The DC signal: Event 4769 and the encryption-type field

Every service-ticket request is logged as **Event ID 4769** ("a Kerberos service ticket was requested"). On a busy domain this is a wall of legitimate traffic, so you do not alert on the event. You alert on one field: **Ticket Encryption Type**.

- `0x12` is AES256-HMAC-SHA1, the modern default. Slow to brute-force.
- `0x17` is RC4-HMAC, legacy, and much faster to crack offline.

A roaster will often explicitly request RC4 even in an AES-capable domain, because an RC4-encrypted ticket falls to a password cracker far quicker. So in a healthy modern domain where almost everything is `0x12`, a lone `0x17` against a service account is the signal. Not volume. Rarity of crypto, plus the target being a service account.

```
# tally encryption types across all 4769s; the rare one is the lead
4769 events:
  0x12 (AES)  ......  many      <- legitimate
  0x17 (RC4)  ......  one       <- the anomaly
```

A common mistake is to expect a burst: dozens of SPNs requested at once. Real roasts often do look like that, but they do not have to. A single RC4 request is enough. Read the field, not the count.

Once you have the anomalous 4769, three fields answer the "who/what/where":

- the **service name** is the account that got roasted (its hash encrypted the ticket),
- the **requesting account** is the compromised user,
- the **source address** is the workstation the request came from, which is your pivot to the endpoint triage.

One field note on that source address: on dual-stack hosts it is often logged as an **IPv4-mapped IPv6 address**, written `::ffff:` followed by the real IPv4 address. The address is the tail; the `::ffff:` is just a wrapper.

## The endpoint signals: recon and the compiled tool

The DC tells you a roast happened and from which machine. It tells you nothing about how. For that you pivot to the workstation, and you need two different log classes because the attack uses two different kinds of tooling.

**Recon is usually PowerShell, and PowerShell Script Block Logging catches it.** Before roasting, the attacker enumerates the directory for accounts that carry SPNs, the kerberoastable set. This is almost always done with a PowerShell AD-enumeration framework. If Script Block Logging is enabled, **Event ID 4104** records the fully de-obfuscated script content as it is handed to the engine, defeating base64, string concatenation, and compression cradles. The script's on-disk path and the first execution timestamp both surface here, and that timestamp will sit just before the DC's ticket request. Enumerate, then roast.

**The roast itself is often a compiled binary, and PowerShell logging never sees it.** The de facto Kerberoasting tools are compiled executables. A compiled tool does not run through the PowerShell engine, so it leaves no 4104. This is the gap that traps analysts: the recon is logged, the action is not, and it looks like the trail goes cold. It does not. You change log class.

- **Process-creation auditing** (Security Event 4688 with command line, or the equivalent Sysmon event) catches the binary at execution if it is enabled.
- **Prefetch** catches it after the fact. Windows writes a record the first time a program runs, preserving the executable name, its run count, the path it ran from, and up to eight recent execution timestamps. That gives you the tool's full path and when it fired, which lines up within a second of the DC's 4769.

Two practical notes on prefetch. First, since Windows 8 prefetch files are compressed (LZXPRESS Huffman), and some parsers offload decompression to a Windows API call, which means they only work when run on Windows; pick a parser that decompresses natively if you analyze off-host. Second, a prefetch parse prints several timestamps, and they are not interchangeable: the **last run time** is execution; the **volume creation time** is when the disk was formatted and is often months or years before the incident. Quoting the volume-creation time as the execution time is the easy wrong answer.

## The timeline is the proof

Laid end to end, the three sources pin the same act:

```
T+0s    Endpoint: AD-enumeration script loads (PowerShell 4104)   [recon]
T+96s   Endpoint: roasting binary executes (Prefetch last-run)    [action]
T+96.5s DC: 4769, RC4/0x17, service-account target, from endpoint [ticket issued]
```

The half-second between the binary executing on the workstation and the DC issuing the RC4 ticket is the correlation. Two independent hosts, two independent log sources, the same moment. That is what "confirming the finding" means: not a single smoking-gun line, but a timeline that only the real attack could produce.

## Defensive controls, in order of leverage

- **Make RC4 impossible for service accounts.** Set service accounts to AES-only so a downgrade request is rejected outright; then any `0x17` request becomes a clean, unambiguous alert. This is the control that both prevents and detects.
- **Use managed, long, random passwords for service accounts** (group-managed service accounts where you can). An offline crack is only a threat against a guessable password.
- **Write the detection rule:** 4769 with encryption type `0x17` from a non-service principal, weighted higher when several distinct service names come from one source in a short window.
- **Enable and forward Script Block Logging (4104) and process-creation auditing (4688 / Sysmon 1),** and ship both off-host to a SIEM so a local log wipe does not erase the evidence that caught the intrusion.
- **Minimize and audit SPNs.** Every SPN on an account is a kerberoastable target. The fewer that exist, and the stronger their passwords, the less the technique buys an attacker.

## Reusable checklist

- On the DC, do not alert on 4769; alert on 4769 with **encryption type `0x17`**. Rarity of crypto is the signal, not volume.
- From the anomalous 4769, read service name (the roasted account), requesting account (the compromised user), and source address (your pivot). Strip any `::ffff:` IPv4-mapped wrapper.
- Filter `krbtgt` and machine accounts (names ending in `$`) out of 4769 noise.
- On the endpoint, expect recon in PowerShell 4104 and the roast in a compiled binary that 4104 will not show. When the recon is logged but the action is not, change log class to process-creation or prefetch.
- In a prefetch parse, the **last run time** is execution; the **volume creation time** is not. Do not confuse them.
- Build the timeline. The proof is the sub-second alignment between the endpoint execution and the DC ticket request, not any single line.

## Closing

The break is recognition, not a tool: one RC4 ticket standing against a field of AES, a recon script that ran a minute and a half earlier, and a compiled binary that executed half a second before the domain controller issued the ticket. Each source is suggestive alone and conclusive together. The lesson that ports to every AD investigation is that the domain controller sees the request and the endpoint proves the method, and you have to read both. Sometimes the deliverable is the timeline.
