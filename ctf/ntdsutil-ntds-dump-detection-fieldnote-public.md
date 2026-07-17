---
title: "Field note: detecting NTDS.dit theft via ntdsutil (the ESENT trail)"
category: dfir-fieldnote
technique: "OS Credential Dumping: NTDS (T1003.003) via ntdsutil + VSS/ESE"
date: "2026-06-19"
status: complete
tags: [dfir, windows, active-directory, ntds, ntdsutil, esent, vss, evtx, detection, T1003.003]
visibility: "public"
---

# Field note: detecting NTDS.dit theft via ntdsutil (the ESENT trail)

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere. Technique generalized; no target, host, IP, or real identifiers.

There are two common built-in ways to steal the Active Directory database, and they leave **different forensic trails**. The companion note covers `vssadmin` + `copy` (a raw file copy you reconstruct from the `$MFT`). This one covers **`ntdsutil.exe`**, the Microsoft-blessed DC maintenance tool, whose "create full" dump leaves its evidence in the **APPLICATION log under the `ESENT` provider**. Knowing which artifact each tool touches is the whole detection.

## Why this works, and why the trail differs

`ntdsutil`'s dump path still uses Volume Shadow Copy to get a readable, point-in-time image of the locked `ntds.dit`, but it does not just copy the file. It spins up its own **ESE (Extensible Storage Engine) instance** and writes a fresh, internally consistent database to an output directory. ESE logs that database's lifecycle - creation and detachment - so the dump announces itself in event-log data, not just on the filesystem. Because `ntdsutil` ships on every domain controller and is a legitimate admin tool, the activity blends in unless you are watching for it.

## The detection trail (three sources, one timeline)

**1. Service state - the shadow copy service starts.**
The Service Control Manager logs **Event ID 7036** in the System log on service transitions. The signal is the Volume Shadow Copy service entering the *running* state, which `ntdsutil` triggers to snapshot the volume. VSS is **demand-started**, so a 7036 "running" for it is an invocation, not boot noise. Watch for a stale earlier start from a prior incident - take the one in your incident window.

**2. The database create/detach - the ESENT provider.**
This is the heart of the ntdsutil signature, in the Application log:

- **Event ID 325** ("a new database created") fires when ESE creates the dumped `ntds.dit`. The event body carries the **full output path** and the event time is the **creation** timestamp. Several 325s are normal (file-replication and other services run ESE databases); the dump is the one whose identifier is the directory service and whose path is an `ntds.dit` in a **non-standard / temp directory**, not `%SystemRoot%\NTDS`.
- **Event ID 327** ("database engine detached a database") marks **completion** - ESE flushed and released the file, so the dumped copy is consistent and ready for use. Use the detach time for "when was the dump ready," not the create time.

Trap: expect a **pair** of 327s within milliseconds - one for the **output copy** and one for the **VSS snapshot source** the engine read from. The snapshot path lives under a `\$SNAP_<datetime>_VOLUMEC$\...` mount; the real dump is in the attacker's chosen output directory. Pick the output path for the completion answer; the `$SNAP` one is just the read handle closing (and a handy tie back to the 7036 VSS start).

The provider name on these 325/327 records (`ESENT`) is itself the answer to "what source reports database create/detach."

**3. Privilege validation - group enumeration by the dumper.**
Before dumping, `ntdsutil` validates the calling account's rights by enumerating the privileged local groups, logged as **Event ID 4799** (security-enabled local group membership enumerated) in the Security log. Expect the **Administrators** and **Backup Operators** groups. Attribution is by the **caller process** (`CallerProcessName` = the ntdsutil binary), not the group name - legitimate services enumerate those same groups constantly. And mind the fields: `Subject*` is **who** did it, `Target*` is **what** was enumerated. The group names you want are in `TargetUserName`; the account in `SubjectUserName` is the actor, not the answer.

## Tying it to the session (and a Logon-ID lesson)

Every action above is stamped with the session's **Logon ID**. The textbook pivot is to take that ID and find the **4624** logon event with the matching `TargetLogonId` for the session start time.

But the textbook event is not always present. If Logon/Logoff success auditing (4624/4672) is not enabled or forwarded, that pivot returns nothing - which is itself a finding about the host's audit posture. Recover the session start anyway: a Logon ID is minted at session creation and tagged on every later action, so the **earliest event bearing that Logon ID** bounds the logon. A Credential Manager read (Event ID 5379) firing at session setup is a clean logon-time proxy, and persistence artifacts (a scheduled task created, Event ID 4698) appearing seconds later corroborate the session.

## ntdsutil vs vssadmin - which trail to expect

| | ntdsutil "create full" | vssadmin + copy |
|---|---|---|
| reads via | VSS snapshot | VSS snapshot |
| writes via | ESE engine (fresh DB) | raw file copy |
| primary trail | **APPLICATION ESENT 325/327** (path + create/complete) | **$MFT** file-creation record |
| filesystem tell | output `ntds.dit` in a temp/non-standard dir | `ntds.dit` (+ a registry hive) in a user dir, **modified-before-created** copy signature |
| shared tells | SYSTEM 7036 VSS start; SECURITY 4799 Administrators+Backup Operators group enum by the dumping process | same |

If you see ESENT 325/327 for an `ntds.dit` outside `NTDS`, it was an ntdsutil/IFM-style dump. If you see no ESENT events but an `ntds.dit` (often with a `SYSTEM`/`SAM`/`SECURITY` hive) appear in the `$MFT` in a user folder, it was a manual copy. Same goal, different evidence.

## Detection / hardening

- Alert on `ntdsutil.exe` on domain controllers (4688 process creation; command line containing `ac i ntds`, `create full`, or `ifm`). Interactive ntdsutil outside a maintenance window is not routine.
- Detection rule: an **ESENT 325 creating an `ntds.dit` outside `%SystemRoot%\NTDS`** (especially under `\Temp\`), correlated with a VSS 7036 start.
- Alert on reads of paths under `\$SNAP_*` by anything but the backup product, and on a 4799 Administrators/Backup Operators enumeration by `ntdsutil.exe`.
- Turn on and forward **Logon success auditing (4624/4672)** from DCs - so a session start is a recorded fact, not an inference.
- Tier-0 hygiene: restrict interactive logon to DCs; watch for scheduled-task persistence created shortly after an admin logon.

## Portable jq habit

EVTX-to-JSON tooling renders `EventID` two ways - an object `{"#text": N}` when the event has attributes (e.g. a Qualifiers value), a bare number `N` when it doesn't. A filter assuming one shape silently matches nothing on the other. Durable handler:

```text
.Event.System.EventID."#text"? // .Event.System.EventID | tostring
```

## One-line takeaway

ntdsutil-based NTDS theft is a LOLBIN that announces itself in the **ESENT provider**: a demand-started VSS service start, a privileged-group enumeration by the ntdsutil process, and an ESE database **created (325)** then **detached (327)** at an `ntds.dit` path outside `NTDS` - with the snapshot source detaching alongside it. Recognize the tool by where the trail lives: ntdsutil writes through ESE (event-log trail), vssadmin+copy writes through the filesystem ($MFT trail).
