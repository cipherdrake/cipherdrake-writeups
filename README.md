# CipherDrake — Field Notes

Sanitized write-ups from CTF machines (HackTheBox, Hacker101 CTF) and bug-bounty engagements. Every note here generalizes the vulnerability class and the recognition/methodology lessons; none of them name a live program, a real company, or an active/unretired box. See [Sanitization standard](#sanitization-standard) below.

---

## Active Directory — Offense

- [ACL ladder + a credential vault + GenericWrite → Kerberoast → DCSync](ctf/ad-acl-ladder-vault-kerberoast-dcsync-fieldnote-public.md)
- [The AD object-control chain that ends in AD CS ESC9](ctf/ad-acl-chain-to-adcs-esc9-fieldnote-public.md)
- [The credential-laundering chain on an AD box](ctf/credential-laundering-chain-ad-fieldnote-public.md)

## Active Directory — Detection / DFIR

- [One RC4 Ticket in a Field of AES: Detecting Kerberoasting Across the DC and the Endpoint](ctf/kerberoasting-detection-fieldnote-public.md)
- [Pre-Auth Type Zero: Detecting AS-REP Roasting from the Domain Controller Alone](ctf/asrep-roasting-detection-fieldnote-public.md)
- [One Typo, One Weak Password: Reading an LLMNR Poisoning Attack Out of a Packet Capture](ctf/llmnr-poisoning-netntlmv2-fieldnote-public.md)
- [Detecting NTLM relay by the hostname/IP mismatch](ctf/ntlm-relay-hostname-ip-mismatch-fieldnote-public.md)
- [Detecting NTDS.dit theft via volume shadow copy](ctf/vss-ntds-dump-detection-fieldnote-public.md)
- [Detecting NTDS.dit theft via ntdsutil (the ESENT trail)](ctf/ntdsutil-ntds-dump-detection-fieldnote-public.md)

## Web & API

- [Web Cache Deception via Nginx Proxy Cache + Dynamic Content at Static-Extension URLs](ctf/web-cache-deception-nginx-fieldnote-public.md)
- [The API-that-trusts-the-client chain](ctf/api-trust-boundary-chain-fieldnote-public.md)
- [Boundaries enforced in the wrong place](ctf/boundaries-in-the-wrong-place-fieldnote-public.md)
- [Multipart Parser Differentials and Blind-Exfil Routing on CTF Platforms](ctf/multipart-parser-differential-fieldnote-public.md)
- [Client-side JWT secrets and layered access-control gaps](ctf/owasp-a01-criticalops-fieldnote-public.md)
- [Client-Side Role Gate + Predictable Object ID: SQLi Bypass Chained to a BOLA/IDOR](ctf/client-side-role-gate-predictable-id-idor-fieldnote-public.md)
- [Two API Authorization Gaps That Chain: Registration Bypass + File Listing IDOR](ctf/registration-bypass-idor-fieldnote-public.md)
- [Unsigned-token deserialization and reflecting output through an existing render path](ctf/pickle-deserialization-template-reflection-fieldnote-public.md)
- [Render features that shell out, configs that store secrets, and privileged scripts that deserialize](ctf/unsafe-deserialization-privileged-helper-fieldnote-public.md)
- [Response-returning SSRF as a tunnel to an internal service's RCE](ctf/ssrf-proxy-to-internal-rce-fieldnote-public.md)
- [Management-deploy interface on default creds → RCE as the service account](ctf/tomcat-manager-war-deploy-fieldnote-public.md)
- [Form Parser Encoding, IP Allowlist Bypass via Headless Bot, and the Explicit Escaping Bypass](ctf/pumpkinspice-fieldnote-public.md)
- [Print-Protocol Injection, Path-Traversal, and a Security Feature That Leaks Root](ctf/print-protocol-injection-fd-leak-fieldnote-public.md)
- [Counting `../` Instead of Resolving the Path: Upload-Filename Traversal to RCE](ctf/upload-traversal-execution-bypass-fieldnote-public.md)
- [String-boundary checks fall to equivalents, and diagnosing a no-op PoC by reading the binary](ctf/string-boundary-bypass-and-noop-poc-fieldnote-public.md)
- [When the right exploit's check passes but its trigger silently no-ops](ctf/printer-privesc-capability-mismatch-fieldnote-public.md)
- [Debug interpreter with OS primitives = unauth RCE](ctf/forth-diagnostic-interpreter-rce-fieldnote-public.md)

## GraphQL & Object Authorization

- [Hidden Is Not Protected: Relay node(id:) IDOR and the Listing-Filter Illusion](ctf/graphql-node-id-idor-fieldnote-public.md)
- [The Sibling Type That Leaks: GraphQL Private-Field Exposure and the Unenforced Boolean](ctf/graphql-private-field-exposure-fieldnote-public.md)

## Cloud, Containers & Kubernetes

- [App-RCE to host-root via a bind-mounted host home](ctf/container-bindmount-host-escape-fieldnote-public.md)
- [Anonymous kubelet → SA token → create-pods = host root](ctf/k8s-anonymous-kubelet-hostpath-fieldnote-public.md)

## Reversing & Firmware

- [Firmware secrets behind XOR + a hardware-check decoy](ctf/firmware-xor-secret-and-hw-decoy-fieldnote-public.md)

## Mobile

- [Secrets in the Bundle: Why a MAC Key Shipped in an App Is Not Integrity](ctf/h1-thermostat-client-secrets-fieldnote-public.md)

## Bug Bounty Methodology

- [Anatomy of a Clean No-Find: Manual IDOR Recon Against a Hardened GraphQL API](bugbounty/hardened-graphql-idor-fieldnote-public.md)
- [The Self-Alias Wall: IDOR Testing an API That Never Hands You an Object ID](bugbounty/hardened-selfalias-api-fieldnote-public.md)
- [When the Whole Bank Is Hardened: Recon Methodology, PII-Safe Auth Testing, and Knowing When to Stop](bugbounty/hardened-bank-vdp-recon-methodology-fieldnote-public.md)

---

## Sanitization standard

Every note here is deliberately generalized to the vulnerability class and the recognition method, not the target:

- No program, company, box, or platform name where it would identify a live, unretired, or non-public target.
- No real endpoints, domains, IPs, usernames, tokens, or secrets. Illustrative values are clearly fake.
- No verbatim server error strings or response bodies — paraphrased to the general class.
- CTF machines are only written up once retired; anything from an active box is held until it retires.

The specifics are what bite. The lessons are always shareable.

## A note on how these were built

These are written by me (CipherDrake), working through each target by hand — every request sent, every command run, every flag captured personally. Where I used an AI assistant as a guide during a live engagement, it pointed at fields, named vulnerability classes, and explained methodology; it did not run the exploit or submit the answer. That distinction is tracked rigorously in my private working notes and reflected honestly here: these are my findings, not a transcript.

---

More from CipherDrake: [profile](https://github.com/cipherdrake) · [HackerOne](https://hackerone.com/cipherdrake) · [HackTheBox](https://profile.hackthebox.com/profile/019e371d-977c-7043-92f7-806afdc00fb3)
