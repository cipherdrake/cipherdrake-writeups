---
title: "Two Readers, One String: An Address-Validator Bypass That Ends in Template Injection"
author: CipherDrake
category: fieldnote
date: "2026-08-18"
tags: [parser-differential, input-validation, ssti, template-injection, ruby]
status: published
sanitized: true (no target identity, platform, domains, flag values, or payload text)
visibility: public
---

# Two Readers, One String: An Address-Validator Bypass That Ends in Template Injection

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

A generalized field note on a pattern found in a web-app CTF-style exercise. All identifying
detail, target, platform, domains, flag values, payload text, has been replaced with
illustrative equivalents. The lesson is the mechanism, not the target.

## The setup

An application accepts one free-text "email address" style string and makes two decisions from
it in sequence:

1. **A gate that must reject a reserved value.** A hand-rolled regular expression scans the string
   for anything that looks like a domain and rejects the input if a reserved domain
   (`reserved.example`, standing in for the real value) shows up in the result.
2. **A gate, downstream, that must accept the same reserved value.** The string is handed to a
   real, standards-compliant address-parsing library, and a second check requires that library's
   own resolved domain to equal the same reserved value before continuing down the "privileged"
   code path.

Read naively, these look contradictory, nothing should be able to satisfy both at once. That
contradiction is exactly the shape of the bug: the two checks are not reading the same *meaning*
out of the string, even though they read the same *bytes*.

```ruby
RESERVED = "reserved.example"

def gate_one!(addr_text)
  domains = addr_text.scan(/@\s*([a-z0-9.-]+)/i).flatten.map(&:downcase)
  raise "rejected" if domains.include?(RESERVED)
  addr_text
end

def build_message(addr_text)
  m = Mail.new
  m[:to] = addr_text          # a full RFC 5322 parser runs here
  m
end
```

## The differential

**The regex is a rough, ad-hoc approximation of "what a domain looks like." The library is a
complete implementation of an actual address grammar (RFC 5322).** The grammar is much richer
than the approximation, in particular, RFC 5322 permits a parenthesized **comment** almost
anywhere in an address, including inside the domain, and comments are semantically equivalent to
whitespace: they carry no meaning and get stripped.

An address like `person@reserved(a comment).example` demonstrates the split:

- **The regex**, matching a character class that excludes `(`, stops the moment it hits the
  parenthesis. It captures a **truncated** token, not the full reserved domain, just a fragment
  of it. The truncated fragment doesn't match the reserved string exactly, so gate 1's
  string-equality check passes it through.
- **The full parser** treats the parenthesized text as a comment, discards it, and reconstructs
  the complete, correct domain underneath, which does equal the reserved value, so gate 2's
  check is satisfied.

Both gates evaluated the same input bytes. They disagreed anyway, because one of them only
implements a fragment of the grammar the other fully implements.

**The generalized root cause: a security decision was made by an ad-hoc pattern match against a
string that is later handed to a full-featured parser for that exact string format, and the two
do not share a grammar.** This shows up anywhere a string is validated with a regex or a denylist
and *then* consumed by something that fully interprets that string's actual syntax, a URL
denylist checked before a resolver runs, a path check before a filesystem call normalizes the
path, a header check before a mail/HTTP library parses the header. The fix in every case is the
same shape: validate using the exact same parser that will later consume the value, not an
approximation of it.

### Three different inputs defeated the same check, and that is the real argument

The variant above is the one I found. It is not the only one. By the time the exercise was
publicly resolved, **at least three structurally different inputs were known to defeat the same
gate**, and only the first of them was mine, the other two came from other researchers working
the same target, including the officially published solution. I'm recording all three because the
*set* makes a point that no single one of them makes on its own.

| variant | shape | what the pattern-matcher ends up with |
|---|---|---|
| comment **inside** the domain | `person@reserved(x).example` | a **truncated** token, it matched, just not the whole thing |
| comment **immediately after** the delimiter | `person@(x)reserved.example` | **nothing**, the character class fails on the first character and the match never starts |
| an **encoded-word wrapper** around the domain (RFC 2047) | `person@=?x?q?reserved.example?=` | the encoding envelope, never the decoded value underneath |

Three unrelated pieces of the surrounding standards, comments, comment placement, and a
completely separate encoding RFC, each defeat the same check by a different mechanism. One
makes the matcher see the *wrong* thing, one makes it see *nothing*, one makes it see an
*encoded* thing.

**Why this matters more than any individual payload:** it kills the tempting fix. Faced with a
single bypass, the instinct is to patch the pattern, add `(` to the excluded set, handle the
comment case. That instinct loses here, and the three-variant set is the proof: the next input
comes from a part of the grammar the patch didn't anticipate, because the grammar is large and
the pattern is small. **You cannot approximate a grammar with a pattern.** The only fix that
holds is structural, move the security decision behind the same parser that will consume the
value, so there is only ever one interpretation to disagree with.

Practical corollary when you find one bypass of a hand-rolled validator: **keep going.** A second
and third variant, found by a different mechanism, turn "here is a payload you should filter"
into "this control is the wrong shape", which is a materially stronger finding and a much harder
one to argue down in triage.

### The two-way split worth remembering when a bypass search comes up empty

When probing this kind of gate, negative results split cleanly into two failure modes, and
knowing which one you're looking at tells you where to keep searching:

1. **The downstream parser refuses to parse the value at all** (a malformed-header exception, a
   parse error). The first gate becomes moot because the value never reaches the second check in
   a form it can evaluate, this is not evidence the bypass approach is wrong, only that this
   specific malformed variant doesn't survive far enough to matter.
2. **The value parses cleanly, but the first gate's simplistic check still catches it.** This is
   the more informative failure: it tells you the parser accepted something your pattern-matching
   gate is still seeing correctly. If your gate keeps catching the true value after re-parsing,
   the difference you need has to move to a part of the string the pattern-matcher doesn't
   actually read, which, for a domain-focused regex anchored at `@`, means anything to the right
   of that anchor. Time spent varying the *other* side of the string (the part *before* the `@`,
   or unrelated fields) will never produce a result if the check in question never looks there.

## A methodology note that applies beyond this bug: null result vs. negative result

During testing, one candidate was nearly logged as "tried, doesn't work" when in fact the *test
itself* had never executed, a local scripting error threw before the payload ever reached the
thing being tested, so no verdict about the target existed at all. It was caught before being
written up as a conclusion and re-run properly with the tooling error fixed; the corrected run
produced a genuine (if still negative) result.

**A tooling failure that prevents a test from running is a null, not a negative.** "I tried it and
it didn't work" is one of the most dangerous sentences in security testing, because it collapses
two very different situations into one sentence: the payload was rejected by the target, or the
payload never reached the target because a proxy dropped it, a shell mangled a quote, an encoding
step corrupted it, or a script failed to compile. Only the first of those is evidence. Before
recording a dead end, confirm the request/parse/execution actually happened as intended.

## The second stage: interpolate-then-compile

Passing the validator only reached the interesting code path, it did not, by itself, produce
anything. The downstream template rendering held a second, independent bug, in a different part
of the value (a display name carried alongside the address rather than the domain):

```ruby
def render(display_name)
  ERB.new(
    <<~TEMPLATE
      Hello #{display_name}!
    TEMPLATE
  ).result(binding)
end
```

This looks, at a glance, like a template engine being handed user data, which template engines
are designed to do safely. The actual defect is an order-of-operations problem:

1. An unquoted Ruby heredoc interpolates `#{}` expressions **at the moment the heredoc literal is
   evaluated**, before anything else happens to the resulting string.
2. So the untrusted `display_name` is substituted into the string *first*, by the host language
   itself, producing a new string that contains attacker-controlled text as **template source**.
3. Only then is that already-tainted string handed to the template engine (`ERB.new(...)`) to be
   compiled and executed.

**The vulnerability is not the template engine call.** A neighboring code path in the same
application used the identical `ERB.new(...).result(binding)` pattern with no user data
interpolated into it, and was completely harmless. The bug is a template engine being fed a
string that was *assembled by string interpolation from untrusted input before compilation*, the
interpolation and the compilation both happen, in that order, and the vulnerable point is the
interpolation, not the compile call that follows it. This generalizes directly to "never build a
SQL query by string concatenation before handing it to the driver": the API being called
(`ERB.new`, or a SQL execute call) is safe in isolation; what matters is what built the string
handed to it.

Once attacker-controlled text can survive into that position, the fix on the offensive side is
purely a quoting problem, get a template delimiter (`<% %>`/`<%= %>` for ERB, or the equivalent
for whatever engine is in play) to survive whatever transformation the untrusted value passes
through on its way into the template source.

## Two decoys, one lesson

The exercise this note is drawn from also planted two fake "flag" values in the source, one in a
CSS comment near an unrelated stylesheet rule, and a second, identical fake value base64-encoded
and hidden under many blank lines further down the file. The second was clearly the more
dangerous plant: decoding it required noticing an anomaly and doing a small amount of independent
work, which made it feel earned in a way the CSS comment did not. Both were wrong.

**The generalized lesson: effort spent finding a value is not evidence that the value is real.**
A planted value that requires work to uncover produces more false confidence than one on the
surface, not less. The only thing that counts as evidence is an independent oracle, a
confirmation signal from the system itself, a state change that can be verified, output that
proves the code path actually executed, never the amount of digging it took to find the
candidate.

## Generalized lessons

- A validator and the real consumer of the same string will disagree whenever the validator
  implements only a fragment of the consumer's grammar. Validate with the same parser that will
  later consume the value, not an approximation of it.
- A bypass does not have to make a filter see nothing. Making a filter match the *wrong* thing,
  a truncated or partial token that fails an exact-equality check, is just as effective and
  easier to miss during review, because the filter did technically fire.
- When a pattern-matching gate is anchored at a fixed point in a string (e.g. "everything after
  the `@`"), only variation on that side of the anchor can ever change the gate's outcome. Confirm
  what the check actually reads before spending time varying the rest of the string.
- Split negative test results into "the downstream system rejected this" vs. "my own tooling
  never actually delivered this" before recording either as a dead end. The second is a null
  result, and treating it as a negative can close off the actual answer.
- Interpolating untrusted input into a string before that string is compiled or executed by a
  template engine, query driver, or interpreter is the vulnerability, regardless of how safe the
  API that eventually consumes the string looks in isolation. Audit what built the string, not
  just what runs it.
- A planted decoy that takes real effort to uncover is more convincing than an obvious one, not
  less. Treat "I had to work for this" as no evidence at all; only an independent, verifiable
  oracle settles whether a find is real.

## Remediation

- Validate user-supplied structured strings (addresses, URLs, paths, headers) by round-tripping
  them through the exact parser/library that will later consume them, rather than reimplementing
  a fragment of that format's grammar as a regex or denylist.
- Never build a string destined for a template engine, query interpreter, or shell by
  interpolating untrusted input into it before the compile/execute step. Pass untrusted data in as
  data, named locals, bound parameters, after compilation, not as part of the source text being
  compiled.
- Treat any point where user input reaches a compile-and-execute call as a code-execution sink,
  regardless of how far upstream the string was actually assembled; the audit trail from
  "attacker input" to "compiled template source" is the thing that needs to not exist, not just
  the final call.
