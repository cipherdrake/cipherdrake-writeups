---
title: "Field note: firmware secrets behind XOR + a hardware-check decoy"
category: "field-note"
tags:
  - ctf
  - reversing
  - firmware
  - embedded
  - xtensa
  - xor
  - anti-analysis
visibility: "public"
---

# Field note: a shipped firmware secret behind single-byte XOR, with a hardware check as the decoy

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

## The setup (generalized)

An embedded firmware image for a common microcontroller family. `file` reports nothing useful; the format is read off the SoC's fixed offsets and a `binwalk` pass. The application partition contains strings implying the firmware must run on genuine or emulated hardware, plus a symbol that reads an on-chip hardware identifier. The actual secret is baked into the image and protected only by a single-byte XOR. The hardware check is a decoy - it only picks which message to print.

## The recognition chain

1. **Known SoC = known offsets.** Embedded families have fixed image layouts (bootloader, partition/descriptor table, application region at documented offsets). Recognizing the family off a `binwalk` line turns "`file` says data" into a concrete carve plan.
2. **Get the segment map before disassembling.** The vendor image tool prints the segment-to-virtual-address table. On a RISC-style core, disassembly with the wrong load address is noise. The segment map is what makes offset→vaddr translation - and therefore the whole reverse - possible.
3. **Strings reference through a literal pool, not directly.** On these cores, code loads a pointer to a string from a literal pool, then dereferences it. To find the code that uses a string, search the literal pool for the string's virtual address (little-endian) and xref the pool entry. A direct string xref usually comes up empty.
4. **Follow the path to what actually gates the secret.** A "run me on real/emulated hardware" message plus a chip-ID read is a textbook decoy. The presence of a hardware check does not mean the secret depends on it. Trace the decode routine: here it was a plain XOR loop with a constant key, gated by nothing.

## The tell that names the cipher

A leading run of one repeated character in "decrypted" output is the signature of a single-byte XOR over zero-padding: `0x00 XOR key = key`. Seeing that pad reveals both that the cipher is single-byte XOR and what the key is. From there the decode is a one-liner.

## The lesson that ports

- The presence of an anti-analysis or anti-clone check says nothing about whether the secret actually depends on it. Confirm what gates the data by following the code, not by reading the warning strings.
- On unfamiliar architectures, the reversing bottleneck is address mapping, not logic. Nail segment load addresses and the literal-pool indirection first; the actual algorithm is often trivial once you can read the right bytes.
- Constant-XOR / base64 "protection" in a shipped binary is obfuscation. If you can pull the image, you can pull the secret.

## Remediation

- Never treat XOR or base64 as encryption for a secret that ships inside firmware. Anyone with the image recovers it.
- Secrets that must live on-device belong in the SoC's secure storage - fused key storage, a secure element, or encrypted storage with flash encryption enabled - bound to the hardware root of trust.
- A hardware-identity check that only branches messaging provides no protection for embedded data. Bind the secret to the hardware root of trust or don't rely on the check at all.

## Real-world class

IoT / embedded firmware that embeds API keys, credentials, or unlock secrets and "protects" them with home-rolled obfuscation instead of the platform's flash-encryption and secure-storage primitives. Pull the image, carve the app, decode - the class recurs across consumer devices and appliances.
