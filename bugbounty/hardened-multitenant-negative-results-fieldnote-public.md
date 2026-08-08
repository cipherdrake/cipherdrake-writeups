---
title: "Nine Things a Target That Doesn't Break Will Teach You"
author: CipherDrake
date: 2026-08-08
category: fieldnote
visibility: public
status: draft, recast into article voice before publishing
sanitized: true (no target identity, endpoints, operation names, ids, vendor/product names, or verbatim error strings)
tags: [bugbounty, authorization, multitenant, graphql, methodology, negative-results]
---

# Nine Things a Target That Doesn't Break Will Teach You

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere. No real target, endpoints, operation names, ids, or vendor identity.

Six sessions against a multi-tenant SaaS platform. Fourteen authorization probes, every one refused correctly. One client-side issue that turned out to be inert. Zero submissions.

That is not a wasted engagement, and the reason is worth writing down: most of what went wrong went wrong in *my* reasoning, not in the target. Every one of these mistakes would have produced a false positive or a false negative on a target that actually was broken.

## 1. An error's shape is a hypothesis, not a verdict

Across one API I saw four different responses to "you may not have this":

- a typed authorization refusal naming the caller and the object
- a plain "not found"
- an unhandled null-pointer exception
- complete silence, with an empty result set and no error at all

Three separate times I inferred enforcement state from the shape of an error, and three separate times I was wrong until a controlled experiment settled it. The silent case was the worst, because "no authorization error" reads as "no authorization check." It was not. That resolver applied the caller's scope as a filter rather than refusing the request. Filtering is enforcement that is silent by design.

Error shapes generate hypotheses. Only experiments close them.

## 2. An empty result proves nothing

The single most expensive mistake of the engagement.

I had two accounts I owned, in separate tenants, and a resolver that took a tenant identifier. Query tenant B's identifier from tenant A's session, get zero rows back, conclude enforcement. Except both tenants were brand new and *contained nothing*. Zero rows from a correct scope check and zero rows from a completely absent one are the same zero.

Same trap in three costumes: an empty array, a `NOT_FOUND` on an identifier that did not exist, and a zero count. All of them feel like evidence. None of them are.

## 3. The experiment design that actually works

Five steps, and steps 1 and 4 are the ones people skip:

1. **Positive control.** Prove the resource is visible to the query *at all*, from a session that legitimately owns it.
2. **Identity fingerprint.** Prove which account the test session is, from the server's own response.
3. **The decisive request**, byte-identical to step 1, from the other session.
4. **Negative control.** The same query against an empty resource of the same type.
5. **Fingerprint again**, proving the session did not change mid-experiment.

Without step 1, a zero is indistinguishable from an unindexed record. Without step 4, a zero has no baseline. Without 2 and 5, you are asserting which account you were rather than demonstrating it.

To make the oracle live I had to create one real record in one tenant, so that "empty" and "non-empty" were finally different states. That is a production write, and it goes in the disclosure list — but without it the whole comparison was two zeros.

## 4. Prove the session, do not remember it

I got the session wrong three times. Once I was certain which browser a proxy tab was authenticated as, said so, and was wrong.

The fix costs one request: send something you *know* is refused cross-tenant, and read the identity out of the refusal. The server tells you who you are. Then the answer is evidence rather than recollection, which also matters when a triager asks how you know the request came from the account you claim.

Related: reusing one proxy tab across two accounts is how the confusion happens. Every time you refresh a tab from a browser, the tab silently adopts that browser's credentials. The tab's *name* does not change. One tab per identity, fingerprinted after every refresh.

## 5. Validation errors are a schema read, with limits

Introspection disabled does not mean the schema is hidden. Send an input object with no fields and the validator names the first required field and its type. Add it, resend, get the next one. Free schema reconstruction, one request per field.

It does **not** work on enums. Invalid enum members came back as a generic type error that never named the legal values. Enum members had to come out of the client bundle instead.

Worth knowing which half of the trick works before you spend requests on it.

## 6. Static analysis misses anything assembled at runtime

I pulled 447 JavaScript chunks and grepped them thoroughly for API routes. The list I built was confidently incomplete.

Routes constructed as `${base}/${id}/${resource}` never appear as literal strings, so grep cannot see them. I only found an entire class of endpoints — including the most interesting one on the target — by *using the application* with the proxy running and watching what it actually sent.

Static and dynamic are complements. A bundle grep gives you a floor, never a ceiling.

## 7. Names that describe a privilege are not checks that enforce one

Three times on this target, a naming convention looked exactly like a security boundary:

- two operations distinguished only by a `...ForStaff` suffix — which turned out to hit the *same* resolver, because operation names are client-side labels the server never treats as identity
- two differently-named fields for the same value, one apparently privileged — no schema-level restriction on either
- a tenant identifier passed as an explicit filter field, as though the client were choosing its own scope — which the server ignored in favour of the token

Suggestive naming generates lead after lead, and on a well-built target every one of them dies. Budget accordingly.

## 8. Argument shape is not a predictor on a mature codebase

"Tenant id buried in a generic filter array or input object rather than a dedicated named argument" is normally a decent bet, because framework authorization rules key on argument names.

It failed twice here. The authorization layer extracted the tenant identifier from wherever it sat in the argument tree and typed it correctly regardless. Once you have seen that happen twice, shape-based hypotheses on that target are worth nothing and you should stop spending requests on them.

## 9. A client-side flaw with a dead sink is not a vulnerability

The one genuine defect I found: a widely-deployed third-party script registered cross-frame message handlers and never compared the sender's origin to anything. Anything that could reach the page could inject messages. And the handler merged attacker-supplied data *over* the legitimate payload, so injected values overwrote real attribution fields.

Both halves of the hypothesis, confirmed empirically.

Then the resulting request returned `404`. The endpoints those handlers post to do not exist. The code path is vestigial. An attacker can make a page emit a forged request that the server discards.

The question that killed it is the one to ask first, not last: **what does the attacker gain that they did not already have?** The sink was unauthenticated anyway — anyone could have posted to it directly, if it had existed. The missing origin check granted no new capability. Real defect, no impact, Informational.

## The meta-lesson

Two days in, the honest summary was "this target's access control is sound, across every parameter shape, both application stacks, three backend services, reads and writes, and both directions." That is a *result*. It says where not to spend the next engagement, which is worth more than another twenty inconclusive probes on the same class.

The trap in a long engagement is that sunk cost starts arguing for you. You have two accounts provisioned, a working harness, hours invested — and a marginal finding starts looking submittable. Every gate above exists to stop exactly that. A clean negative you can defend is better than a Low you cannot.

Also: a client-side testing harness is worth building once and keeping. Mine failed for two sessions before I read enough of the target's own code to find the reason — the script deliberately refuses to initialise on `localhost`, on IP literals, and on CMS admin paths, which is sensible analytics hygiene and completely invisible from the outside. A hosts-file entry mapping a real-looking name to loopback fixed it in one line. Test-environment exclusions are not security controls, but they will absolutely stop you reproducing something that is genuinely there.
