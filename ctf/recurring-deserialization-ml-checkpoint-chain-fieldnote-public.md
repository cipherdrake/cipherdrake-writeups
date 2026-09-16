---
title: "Field note: the same deserialization bug, three different components, three trust boundaries"
author: CipherDrake
category: "web"
vulnerability_class: "Insecure Deserialization (CWE-502)"
date: "2026-07-20"
status: "complete"
tags:
  - ctf
  - web
  - deserialization
  - pickle
  - ml-security
  - path-traversal
  - fieldnote
visibility: "public"
---

# Field note: the same deserialization bug, three different components, three trust boundaries

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

## The shape of it

A file-upload application processed submitted documents with a document-parsing library, and that library had a known deserialization vulnerability (a publicly disclosed CVE, patched in a later version): a value pulled from inside the uploaded document was used to build a filesystem path, and whatever was found at that path got unpickled without any validation. Pickle-style serializers reconstruct arbitrary objects, including objects whose reconstruction process calls an arbitrary function with arbitrary arguments, so an attacker who can get the right bytes onto disk at a path the parser will look up gets code execution the moment that document gets processed.

Getting there took most of an engagement, because the upload handler in front of that parser was genuinely well defended, better defended than it first appeared, and the story of *how* that became clear is the actual point of this note. Once the foothold landed, the interesting part continued: a privilege-escalation chain that ran through an unrelated second component with a completely different vulnerability class (a path-traversal bug that happened to leak a credential), landing on a third instance of the exact same root cause, an ML framework's model-checkpoint loader, unpickling a "trained model" file with the same zero integrity checking as the original document parser. Same bug, three separate places, three separate trust boundaries. That's the lesson worth carrying forward, more than any of the individual mechanics.

## Self-correction #1: a conclusion reinforced by volume, not isolation

The upload handler accepted several file types and rejected anything whose declared type didn't match its content, along with anything whose filename tried to traverse directories, inject shell metacharacters, or smuggle a target extension past an allowlist through several different tricks, parameter pollution, an alternate filename-encoding header, null-byte truncation, a substring-containment bypass. Every one of those attempts against the specific target extension needed for the exploit came back rejected, identically, roughly ten times in a row across different techniques.

The natural read of that pattern is "the extension allowlist is solid." It felt earned, ten independent techniques, one consistent outcome. It was wrong, and the reason it was wrong is the actual lesson: every single one of those ten attempts also happened to use non-conforming file content, placeholder bytes, plain text, anything that wasn't genuinely valid data of the target file type, declared under the target extension. Nobody had ever isolated "is the extension check itself the block" from "is the content-validity check the block," because every test changed the filename while leaving the content wrong. When a direct test finally controlled for that, genuinely valid bytes, target extension, nothing else varied, it uploaded cleanly on the first try. The "solid allowlist" had never been isolated from a completely different, already-known check (content-sniffing) that was doing all the actual rejecting.

**The portable lesson:** a control that survives many attempts is not the same as a control that has been tested in isolation. If every failed bypass attempt against one check shares an untested assumption, the volume of failed attempts proves nothing about that specific check, it just means nobody varied the one variable that mattered yet. Before concluding a defense is solid, ask what every failed test had in common besides the technique being tried.

## Self-correction #2: a timing signal that looked clean and wasn't

Separately, earlier in the same engagement, a timing side-channel was built to test whether the document-parsing library was processing file content it technically shouldn't have had access to yet (a question relevant to figuring out the delivery mechanism). A single trial of each of three conditions produced a strikingly clean, three-way separation in response times, fast, medium, slow, in exactly the order a working theory predicted. That looked like a genuine oracle: a way to test, via timing alone, whether a hypothesis about backend behavior was correct, without needing any other observable signal.

It didn't survive replication. Repeating two of the three conditions twice each produced heavily overlapping ranges, one repeat of the condition that was supposed to be "fast" came back slower than both repeats of the condition that was supposed to be "slow." The clean separation had been one lucky sample per condition, not a real, repeatable effect. Everything built on top of that signal in the meantime, several follow-up tests trying to use the "oracle" to answer other questions, had to be retracted as unconfirmed, not disproven; there was simply no reliable way to have tested those questions with the tool being used.

A later, unrelated piece of investigation (reading source code that became readable after the eventual foothold) explained why the signal never held up: the timing being measured had no causal relationship to the hypothesis being tested at all. The thing believed to be creating the timing difference wasn't involved in the request-response cycle being measured, it ran on a completely separate, asynchronous schedule. The retraction from the replication check was correct on its own; the later explanation just confirmed there had never been a real signal available to find in the first place, for a reason that had nothing to do with sample size.

**The portable lesson:** a clean-looking single-trial timing separation is not evidence, it's a hypothesis. Repeat before trusting it, especially when a theory "predicts" the exact ordering observed, that's exactly the situation where confirmation bias makes one lucky sample feel decisive. And when a black-box timing signal doesn't replicate, don't just discard the data, stay open to the possibility that the mechanism you assumed was causing it was never in the causal path at all, which a later look at real internals may confirm outright.

## The throughline: insecure deserialization is a pattern, not a single bug

The foothold vulnerability was unsafe deserialization in a document parser: a value from inside an uploaded file controlled which serialized object got loaded and executed. The privilege-escalation path that followed ran through an entirely different bug in an entirely different component, a path-traversal flaw in a lightweight file server (a check for `../` that ran *before* the input was decoded, so an encoded form of the same traversal sequence sailed straight through). That traversal wasn't itself a deserialization bug, but its payoff was unusually high: it read a private credential file sitting on a filesystem the traversal was never supposed to reach, and that credential turned out to grant legitimate, non-containerized access to a much more privileged context.

From there, the actual escalation to full privilege ran through a *third* instance of the same root cause as the very first bug: an ML framework's checkpoint-loading utility, configured to automatically load whichever "trained model" file had the most recent modification time from a shared directory, with zero signature or integrity verification. On the legacy serialization format many ML frameworks still support for backward compatibility, a model checkpoint file is, underneath, just a pickle stream. The exact same `__reduce__`-style code-execution primitive that worked against the document parser worked identically against the checkpoint loader, same technique, different file extension, different library, same underlying design mistake, running as a much higher-privileged process.

**The portable lesson, and the real point of writing this note:** "insecure deserialization" is not a single vulnerability to patch once and move on. It's a design pattern, any place an application automatically loads and reconstructs previously-serialized state from disk, without verifying that state hasn't been tampered with, is a candidate for this exact bug class, regardless of the specific format or library. Cached parse results, session objects, message-queue payloads, and, increasingly relevant as more applications ship ML components, model checkpoints are all the same shape of risk. Finding one instance of this pattern in an application is a strong reason to go looking for a second one in any other component that also loads serialized state from a shared or attacker-influenced location, rather than treating the first find as the whole story.

## Key lessons

- **A control that has survived many failed bypass attempts has not necessarily been tested in isolation.** If every failed attempt against one check shares an untested assumption, check that assumption directly before trusting the volume of failed attempts as proof the check itself is solid.
- **A clean single-trial timing separation is a hypothesis, not evidence, repeat it before trusting it**, especially when the result matches a theory's prediction exactly. That's precisely the shape confirmation bias takes.
- **When a black-box signal fails to replicate, and source or internal detail later becomes available, check whether the mechanism assumed to cause it was ever actually in the causal path.** Sometimes the honest answer is "there was never a real signal there to begin with," which is a stronger and more useful finding than "the effect is just noisy."
- **A traversal or containment check that validates the raw input before decoding it (URL-decoding, path normalization, or any other transform) can be bypassed by an encoded form of the exact input the check was written to block.** Validation has to run after full decoding, not before.
- **Any credential or key readable via a file-disclosure primitive should be assumed live until proven otherwise.** A read-only bug that reaches a private key file is not "just an information leak", test whether the leaked material is usable, immediately.
- **Insecure deserialization is a pattern, not an incident.** Finding it once in an application is a reason to actively look for it again in any other component that loads serialized state from disk automatically, including ML model-checkpoint loaders, which are an increasingly common and currently underdiscussed instance of exactly this bug class.

## Remediation, generalized

- Never construct a filesystem path or lookup key from data inside an untrusted document, request, or upload, and then use that path to load and deserialize a file with a format capable of reconstructing executable behavior. Treat any deserialize-from-resolved-path call as dangerous by default.
- Any check meant to constrain the *type* of accepted content (an extension allowlist, a content-type check) should be verified against the actual bytes being written to disk, tested in isolation from any other validation layer the application also performs, so a passing test can't be silently riding on a different check having done the real work.
- Path and traversal validation must run after all decoding transforms are applied to the input, not before, check the fully-resolved final path is a descendant of the intended root directory, not that the raw input string looks clean.
- Treat model-checkpoint loading, cache deserialization, and any other "load previously-saved state from disk" code path as a deserialization attack surface requiring the same integrity controls as a network-facing endpoint: cryptographic signing and verification before load, not just after-the-fact scanning.
- When investigating black-box timing behavior, budget for replication before drawing conclusions, and treat a clean single-trial result with the same skepticism as a noisy one until it's been repeated.
