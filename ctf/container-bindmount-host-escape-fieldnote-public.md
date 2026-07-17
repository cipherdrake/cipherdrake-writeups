---
title: "Field note: app-RCE to host-root via a bind-mounted host home"
category: "field-note"
tags:
  - ctf
  - linux
  - ssti
  - docker-escape
  - bind-mount
  - suid
  - password-reuse
visibility: "public"
---

# Field note: container-root + a bind-mounted host home = host root

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

## The chain (generalized)

An external web app has an injection bug (SQLi) that yields an admin session and a recoverable password hash. That password is reused on a second, internal-only app that appears only after authenticating to the first. The internal app has a server-side template injection that runs code - but as root inside a container, not on the host. The container has a host user's home directory bind-mounted in. That mount, plus SSH listening on the container bridge, is the escape to host root. No kernel exploit.

## The recognition calls that matter

- **Size-filter fuzzing when the app returns 200 for everything.** A `200` on a random path means content discovery has to filter by response size, not status code. Baseline a known-bad path, filter that length out.
- **Store-then-render vs render-on-submit are different code paths.** A template/eval injection can be dead in the page that later *displays* a value but live in the response to the request that *submits* it. If a probe shows up literally on a GET, re-test the POST/PUT response itself before declaring it not vulnerable. This is the single most missable part of the chain.
- **A bind-mounted host directory writable by container-root is a host-write primitive.** On a container file, an owner UID like `1000:1000` (a normal host user, not root) is the tell that a host home is mounted in. Container-root can write anything into it, and the host sees those writes as that user.
- **"SSH refused on the public IP" is not "SSH is closed."** From wherever you have code execution, check the internal/bridge interfaces. Host SSH bound to the container gateway means the pivot must originate inside the container.

## The two generic escapes off a writable host-home mount

Both work regardless of the app that got you container-root:

1. **authorized_keys write.** Drop your public key into the mounted user's `~/.ssh/authorized_keys`, fix perms/ownership to the user's UID, then SSH from inside the container to the host gateway as that user.
2. **Root-owned SUID drop.** Place a SUID-root binary in the mounted directory and execute it from the host as the mounted user. Two gotchas: the binary must come from the *host's* filesystem (a binary copied out of the container dies on the host with a missing-library error - it must match the filesystem that executes it), and the shell must be invoked with the privilege-preserving flag or it drops its effective UID on startup.

## The lesson that ports

- A bind mount is a two-way trust relationship. Mounting a host path into a container where code runs as root hands container-root an arbitrary-write primitive against that host path - `~/.ssh` and SUID drops are the immediate wins.
- Credential reuse between an "external" and an "internal" application tier collapses the boundary between them. One recovered hash unlocked the internal app purely by reuse.
- Keep the execution context explicit when pivoting through a container: which filesystem holds the key, which network reaches the gateway, which identity runs the command. Most of the failed attempts in this class are context confusion (attacker vs container vs host), not missing access.

## Remediation

- Run container workloads as a non-root user (`USER` in the image) so an app-level RCE is not container-root and cannot abuse writable mounts.
- Never bind-mount host home directories, `/root`, the container runtime socket, or config dirs into an app container. If a mount is unavoidable, make it read-only and run the process as a UID that doesn't match the host owner.
- Don't expose host SSH on the container bridge network.
- Use distinct credentials per application tier; parameterize the injectable query that starts the chain; and render user input as data, never compile it as a template.

## Real-world class

Hand-rolled container setups (compose files) that run the app as root and bind-mount a host path straight through, combined with credential reuse across an internal/external app split and SSH reachable on the bridge. The misconfiguration is common because bind mounts are the easy way to share data, and "run as root" is the path of least resistance in a Dockerfile.
