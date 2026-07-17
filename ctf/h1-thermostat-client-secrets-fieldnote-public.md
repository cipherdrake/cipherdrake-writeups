---
title: "Secrets in the Bundle: Why a MAC Key Shipped in an App Is Not Integrity"
date: 2026-06-18
tags: [appsec, mobile, android, reverse-engineering, hardcoded-secrets, client-side-secret, mac, integrity, methodology]
status: draft (neutral / voice-agnostic; recast into article voice before publishing)
sanitized: true (no target identity, platform, package name, endpoints, header names, or real flag/key values)
visibility: public
---

# Secrets in the Bundle: Why a MAC Key Shipped in an App Is Not Integrity

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere. No real target, platform, package, endpoints, or secret values.

A mobile app is a file you hand to the attacker. Everything compiled into it - strings, endpoints, API keys, and any cryptographic key - travels with it and comes back out with a decompiler. The most reliable mobile finding is not a clever runtime exploit; it is reading a secret the developer believed was hidden because it was "inside the app." This note is the pattern, the three-step read that finds it, and the specific trap of a request-signing key that ships in the client.

## The shape of the target

A thin mobile client whose job is to talk to a backend. The manifest asks for network access and little else. There is no exposed inter-app surface to attack: nothing the platform marks as callable by other apps, no custom link handlers. The interesting material is entirely in the code's network and secret layer.

That is a feature, not a dead end. When a client has no inter-process surface, the whole hunt collapses to: decompile, read how it builds requests, and read what it embeds.

## Why the manifest comes first

The app's manifest is a map, and it scopes the entire engagement before you read a line of logic:

- The permissions tell you what the app is for. A network permission and almost nothing else means the app's purpose is a backend conversation.
- The list of components other apps can invoke tells you whether there is an inter-app attack surface at all. If nothing is exported and there are no custom link handlers, you can cross the entire inter-process attack class off the list in one read.
- A flag that allows plaintext network traffic tells you the transport is observable and modifiable, which makes a dynamic replay path free if you want it later.

What the manifest does *not* declare narrows the hunt as much as what it does. Here it pointed straight at the code.

## The three-step read

1. **Treat the package as an archive and decode it.** A mobile app package is a ZIP. Unpack it, decode the resources and manifest to readable form, and decompile the bytecode back to readable source. Two standard tools do this for Android (one for resources/manifest, one for code).

2. **Find the request builder.** Grep the decompiled source for URL schemes, endpoint paths, and secret-shaped words (key, token, secret, authorization). Ignore the resource-ID file noise. One class almost always assembles the outbound request: it holds the base URL, sets the headers, and serializes the body. Read it.

3. **Read what it embeds.** Two kinds of secret routinely fall out here:
   - **A value shipped as a static header or constant.** Developers sometimes attach a token or identifier as a fixed header on every request. It is a string literal in the binary; you read it directly.
   - **A key used to compute a request signature.** This is the subtle one, covered next.

No live request is required to recover either. The decompiler is the exploit.

## The trap: a request-signing key in the client

A common "anti-tamper" pattern: the client computes a signature over each request and sends it in a header, so the server can "verify the request was not modified." Concretely the client does something like:

```
signature = base64( hash( SECRET_KEY + request_body ) )
```

with `SECRET_KEY` hardcoded in the app (illustrative, not a real value):

```
SECRET_KEY = "example-not-a-real-key-0000"
```

This looks like integrity protection. It is not. A message authentication code only authenticates anything if the key is secret *from the party producing the signature*. Here the producing party is the client, and the key ships inside the client. So any user can:

1. Decompile the app and recover `SECRET_KEY`.
2. Construct any request body they like - including values the app's UI never sends.
3. Compute a valid signature over it with the recovered key.
4. Send it. The server validates the signature and trusts the forged request.

The signature raised the effort to "read one string." It authenticated nothing. Worse, it can create false confidence that leads the backend to *skip* real authorization checks because "the request is signed."

## Why it held together wrong

The defender conflated two different properties:

- **Obfuscation / encoding** (base64 a payload, hash it with a key) feels protective because the wire format is not human-readable. But every step is a reversible, client-side transform. Encoding is not confidentiality, and a client-computed signature is not authentication.
- **Integrity from the client's perspective** is meaningless. The threat model for a mobile client is that the user *is* the attacker and controls the device, the binary, and the runtime. A secret known to the attacker is not a secret.

The control that was missing is server-side: authorization on every action the API accepts, evaluated against an authenticated principal, never inferred from the presence of a client-computed signature.

## Reusable checklist

- Read the manifest first. Permissions scope the purpose; the exported-component list tells you if there is any inter-app surface; a cleartext-traffic flag tells you the transport is open. Absence narrows the hunt.
- A package is a ZIP. Decode resources/manifest and decompile the code before assuming you need the live backend.
- Grep the decompiled source for URL schemes, endpoint paths, and secret-shaped words. Filter out resource-ID noise. Read the class that builds the request.
- Recover anything shipped as a constant: static headers, tokens, keys, endpoints. Those are findings on their own.
- When the client computes a signature, ask one question: where does the key live? If it is in the client, the signature authenticates nothing and you can forge valid requests.
- "Encoded" and "signed by the client" are not "secret" and not "authenticated." Treat both as plaintext you happen to have to decode.
- The cleartext-traffic flag plus a known endpoint plus the recovered key makes a forged-request dynamic path trivial when you want it.

## For defenders

- Keep secrets server-side. The client should hold, at most, per-user credentials obtained at runtime, never a shared key compiled into the build.
- Do not use client-side signing as integrity or anti-tamper. If you need integrity, it has to be rooted in something the client cannot extract; a baked-in key is not that.
- Authorize every action on the server against the authenticated user. Never trust a request because it carries a valid client-computed signature.
- If platform-level assurance matters, use the OS attestation services rather than a homemade signature, and design as if the client is fully attacker-controlled - because it is.

## Closing

The break was recognition, not a payload: decompile a client that has no inter-app surface, read the class that builds its requests, and notice that one header is a secret shipped verbatim and another is signed with a key that also ships in the app. A signature whose key lives in the client is theater. On any mobile target, decompile and read the request builder before you touch the backend - the hardest-looking secret is often the one already in your hands. Sometimes the deliverable is the method.
