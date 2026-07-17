---
title: "Field note: render features that shell out, configs that store secrets, and privileged scripts that deserialize"
category: fieldnote
tags:
  - fieldnote
  - command-injection
  - pdfkit
  - cve-2022-25765
  - credential-reuse
  - insecure-deserialization
  - yaml
  - privilege-escalation
visibility: public
---

# Render features, stored secrets, and privileged deserializers

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

A short field note on three trust failures that chain cleanly, drawn from a Linux web box. None of them is memory corruption; all three are things a real application or admin does. Values below are illustrative.

## 1. A feature that shells out is a command-injection surface

"Convert this URL to a PDF," "screenshot this page," "resize this image" - these features almost always shell out to a renderer (`wkhtmltopdf`, headless Chrome, ImageMagick). If the library builds a shell command from user input and validates the input only as "looks like a URL," shell metacharacters in that input execute.

The `pdfkit` gem `< 0.8.6` is the canonical example (**CVE-2022-25765**): it passes the URL to `wkhtmltopdf` through a shell without sanitizing metacharacters. A URL like:

```text
http://?name=%20`command_here`
```

passes the weak `\Ahttps?://` check (empty host is fine) and executes `command_here`. The leading `%20` is the shell-argument break that separates the injected command as its own token.

Recognition call: test any URL/filename parameter on a render/fetch feature with command-substitution metacharacters (`` ` `` and `$()`) before anything else.

## 2. When a metacharacter payload silently fails, suspect an encoding layer before the vuln

A payload that should fire but returns a generic "couldn't load that" with no callback is often mangled in transit, not blocked. Web frameworks URL-decode a request body **once** before the value reaches the sink. Two consequences:

- To land a **literal** `%20` at the sink, the wire must carry `%2520` (the framework decodes it back to `%20`). Sending a raw space instead decodes to a raw space at the sink and can break the input's own validation.
- Any `&` in the payload (e.g. `0>&1` in a bash reverse shell) must be encoded to `%26`, or the framework splits the body at the field separator and truncates the payload.

Isolate transport encoding from the bug when a metacharacter payload fails quietly. In an intercepting proxy, type the readable payload with a literal `%20`, select the value, and URL-encode it once more - that second encode is what survives the decode.

## 3. Dependency/package tooling leaves plaintext credentials in dotfiles

Package managers persist credentials for authenticated sources in predictable, plaintext dotfiles: `.bundle/config` (Ruby/Bundler), `.npmrc`, `.pypirc`, `.git-credentials`, `.netrc`. After any foothold, grep every home directory for these. The credential is frequently reused as the owning user's login, turning one readable file into a full account pivot.

## 4. A privileged script that deserializes a relative-path file is root RCE

The high-value chain link. A helper script runnable as root (e.g. via `sudo` NOPASSWD) that does:

```ruby
YAML.load(File.read("some_file.yml"))   # unsafe loader, RELATIVE path
```

has two problems: `YAML.load` (unlike `YAML.safe_load`) instantiates **arbitrary Ruby objects**, and the relative path is read from the current working directory - attacker-controlled. Run the script from a directory you own, drop a malicious file there, and a public gadget chain (built-in classes whose construction side-effects reach `Kernel.system`) executes your command as root during the load itself.

This generalizes across ecosystems: unsafe deserialization is `YAML.load` / `Marshal.load` (Ruby), `pickle.load` (Python), `readObject` (Java), `unserialize` (PHP). The recognition tell is the **missing leading `/`** on the input path combined with a loader that reconstructs objects rather than plain data.

A clean cash-in that avoids handling secrets: have the gadget drop a SUID shell (`cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash`), then run `/tmp/rootbash -p`. The `-p` preserves euid=0 rather than dropping privileges on startup.

## Defensive summary

- Patch shelling-out renderers and pass arguments as an array, never a shell string; strictly allowlist URLs/filenames.
- Never persist package-source credentials in plaintext, and never reuse a service credential as a user login.
- Replace `YAML.load` with `YAML.safe_load` and equivalents; never deserialize attacker-influenced input with an object-instantiating loader.
- Privileged helper scripts read config from a fixed absolute path and run with least privilege - not blanket `sudo` NOPASSWD on an interpreter.
