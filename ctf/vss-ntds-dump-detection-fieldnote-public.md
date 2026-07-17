---
title: "Field note: detecting NTDS.dit theft via volume shadow copy"
category: dfir-fieldnote
technique: "OS Credential Dumping: NTDS (T1003.003) via VSS"
date: "2026-06-19"
status: complete
tags: [dfir, windows, active-directory, ntds, vss, shadow-copy, evtx, mft, detection, T1003.003]
visibility: "public"
---

# Field note: detecting NTDS.dit theft via volume shadow copy

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere. Technique generalized; no target, host, IP, or real identifiers.

A domain admin (legitimate or compromised) can dump the entire Active Directory credential store using only built-in Windows tooling - no malware. The pattern: create a volume shadow copy of the system volume, mount the snapshot, and copy `ntds.dit` plus the `SYSTEM` registry hive out of it. The pair is everything an offline `secretsdump` needs. This note is the detection trail it leaves, reconstructed from host logs and the MFT.

## Why this works

`ntds.dit` is locked while the directory service runs and is encrypted at rest with the domain bootkey. A shadow copy provides a stable, readable point-in-time image of the locked file, and the bootkey is derived from the `SYSTEM` hive - so an attacker grabs both. Volume Shadow Copy ships on every Windows Server, which makes this a living-off-the-land credential theft that bypasses file locks and AV-on-write.

## The detection trail (four sources, one timeline)

**1. Service state - the shadow copy service starts.**
The Service Control Manager logs **Event ID 7036** in the System log on every service transition. The signal is the Volume Shadow Copy service entering the *running* state. The recognition that matters: VSS is **demand-started**, not boot-started. So a 7036 "running" for it is something *invoking* it, not routine startup. Anchor it against the boot service storm - the cluster of services that all flip to running in the same second is startup; a lone service starting later was triggered.

**2. Privilege validation - group enumeration by the VSS process.**
When VSS builds a snapshot it validates backup rights by enumerating the privileged local groups, logged as **Event ID 4799** (security-enabled local group membership enumerated) in the Security log. Expect the **Administrators** and **Backup Operators** groups, enumerated by the **machine account** (`HOST$`, SID `S-1-5-18`).
Attribution trap: 4799 is noisy - several legitimate services enumerate those same groups routinely. The signal is the **caller process** (`CallerProcessName` = the VSS service binary), not the group name. Filter on the process that did it, not on the group that was read.
Bonus: that same 4799 carries the VSS process PID in `CallerProcessId`, logged in **hex** (as Windows security-event PIDs always are - `printf "%d"` to convert).

**3. Volume mount - the snapshot gets an identity.**
The NTFS Operational log records volume mounts (**Event ID 4**). When the shadow copy mounts it appears as a `HarddiskVolumeShadowCopyN` device.
Trap: the obvious populated `VolumeId` on a normal `HarddiskVolumeN` device is the **persistent backing volume** (its timestamps go back to the host's build date) - not the snapshot. The shadow copy device often has a **null `VolumeId`**; its identity lives in `VolumeCorrelationId`, and it is only meaningful at the **mount timestamp**. Distinguish volumes by device + time, not by which field happens to be populated.

**4. The files on disk - MFT confirms the exfil copy.**
Parse the `$MFT` and look for `ntds.dit` written **outside its home** (`%SystemRoot%\NTDS`). A real install has a handful of legitimate `ntds.dit` records (live DB, a System32 copy, WinSxS install templates) - all created at build time. The dump is the one in a **user-writable directory, created in the incident window**. Right next to it: a `SYSTEM` hive (and sometimes `SAM`/`SECURITY`). NTDS + a registry hive co-located outside their normal paths is the secretsdump signature - neither decrypts alone.

## The two highest-value tells

- **Same-millisecond pin.** The NTFS snapshot-mount time and the MFT `ntds.dit` creation time match to the millisecond. That cross-source correlation is the proof the file came out of the snapshot, stronger than any single log line.
- **Modified-before-created.** Both copied files show `$SI` *Modified* earlier than `$SI` *Created* - physically impossible for an original file. `copy`/`robocopy` carries the source's modified time forward while stamping a fresh created time on the duplicate. Any file whose modified predates its created was copied in. (Worth corroborating with `$FILE_NAME` timestamps and a `.lnk`/Recent artifact if Explorer was used.)

## Detection / hardening

- Alert on `vssadmin create shadow` and WMI `Win32_ShadowCopy.Create` on domain controllers - never routine; real backups run through the sanctioned backup product.
- Correlate: NTFS event 4 mounting a `HarddiskVolumeShadowCopy*` device + a VSS 7036 start outside the backup window.
- File-creation / EDR rule: `ntds.dit` or any registry hive (`SYSTEM`/`SECURITY`/`SAM`) written outside `%SystemRoot%\NTDS` and `%SystemRoot%\System32\config` - especially in a user profile.
- Tier-0 hygiene: restrict interactive logon to DCs; enforce AES, gMSA-managed service accounts, and backup ACL/encryption separation so this path is both unnecessary and anomalous.

## Portable jq habit

EVTX-to-JSON tooling can render `EventID` two ways - an object `{"#text": N}` when the event has attributes, or a bare number `N` when it doesn't. A filter assuming one shape crashes on the other. Durable handler:

```text
.Event.System.EventID | if type=="object" then .["#text"] else . end | tonumber
```

## One-line takeaway

VSS-based NTDS theft is a LOLBIN that leaves a clean four-source trail: a demand-started service start, a group-enumeration by that service's process, a snapshot mount with its own correlation GUID, and two files (database + bootkey hive) copied into a user folder with the modified-before-created copy signature - pinned together to the millisecond.
