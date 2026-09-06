---
title: "Field note: client-side crypto is not a trust boundary, and neither is a filename sanitizer"
author: CipherDrake
category: fieldnote
date: "2026-07-03"
tags:
  - fieldnote
  - public
  - stored-xss
  - client-side-crypto
  - broken-access-control
  - file-upload
  - methodology
visibility: "public"
---

# Field note: client-side crypto is not a trust boundary, and neither is a filename sanitizer

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

Three stacked lessons from one target, each a different flavor of the same underlying mistake: trusting a control that only looks like a boundary.

## 1. If the key ships to the client, the "encryption" is not a trust boundary

A feature encrypted user-provided data in the browser before sending it to the server, using a symmetric key baked into the client-side JavaScript. The server decrypted with the same key and trusted the result as if it had been produced by the feature's intended input path.

The flaw: any code that ships a key to the client can be replicated by any client. Client-side "encryption" of this kind can only ever provide confidentiality against a passive network observer - it cannot provide authenticity (who sent this) or integrity (was this produced the intended way), because the party being authenticated against holds the same key as everyone else. Anything that treats a client-encrypted blob as proof the data passed through some other process (a scanner, a media pipeline, an ML model, a client-side validation step) is trusting a control that provides no such guarantee.

Portable technique: when a target ships an "encrypted" or "signed" client-side artifact, check whether the key or secret used to produce it is present anywhere in the client bundle (JS, app binary, config shipped to the device). If it is, the artifact is forgeable, and any processing step it claims to have gone through (voice transcription, image analysis, whatever) can usually be skipped entirely - construct the expected payload directly instead of driving the intended UI.

## 2. Content that reaches a privileged reviewer is a stored-XSS target, no matter how it got there

A submission feature accepted user content that was eventually reviewed by a privileged operator in an internal dashboard. The content passed through an intermediate processing pipeline before landing in front of that reviewer.

The flaw: the intermediate pipeline had no bearing on whether the final rendering step encoded output correctly. Once the underlying storage/submission mechanism was reached directly (bypassing the pipeline entirely, per lesson 1), arbitrary HTML/JS landed in the reviewer's dashboard unescaped.

Portable technique: any workflow ending in "a privileged user reviews submitted content" is a stored-XSS candidate regardless of the path the content took to get there. Test the raw storage/submission endpoint directly rather than assuming the intended pipeline (upload, transcription, OCR, whatever) constrains the content in some useful way - it usually only transforms it, never sanitizes it.

## 3. A filename sanitizer and an extension allowlist are two different controls

A file-save feature blocked path traversal and stripped special characters from filenames, and this was correctly enough implemented that no traversal or injection via the filename itself was possible. But the sanitizer said nothing about the file's *extension*, and the save directory happened to sit inside a webroot that the same server process both served and executed with elevated privileges.

The flaw: filename sanitization (traversal, special characters) and extension/content-type restriction are separate controls, and hardening one does not harden the other. A perfectly sanitized filename ending in an executable extension, saved into a directory the serving process executes, is still full remote code execution - with attacker-controlled content, since nothing constrained what could be written to the file.

Portable technique: whenever a target exposes a "save this content to a file" feature, test three things independently: does the filename allow traversal, does the filename allow arbitrary extensions, and does the save directory overlap with anything the server executes. A green result on the first does not imply a green result on the other two, and the third question (does execution overlap the write location) is the one write-up authors skip most often.

## Defensive mirror

- Never ship a symmetric key, signing secret, or any authenticity-bearing material to a client. Anything requiring authenticity or integrity checking must be verified server-side against a server-held secret, never a shared one.
- Encode output at render time for every content-rendering surface a privileged user sees, regardless of which ingestion pipeline produced the content. Treat every ingestion path as equally hostile.
- When implementing a file-save feature, enforce a filename allowlist (or at minimum an extension allowlist) as a distinct control from path-traversal protection, and never let a writable output directory overlap with a directory the same process serves and executes - especially not under an elevated-privilege account.
