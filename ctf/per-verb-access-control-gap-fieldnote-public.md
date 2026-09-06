---
title: "The Lock Was on the Wrong Door: When Authorization Binds to One HTTP Verb"
author: CipherDrake
date: 2026-09-06
tags: [appsec, broken-access-control, http-verb-tampering, sqli, blind-sqli, authorization, methodology]
status: published
sanitized: true (no target identity, platform, endpoints, parameters, or ids)
visibility: public
---

# The Lock Was on the Wrong Door: When Authorization Binds to One HTTP Verb

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere. No target, endpoint, or parameter names survive from the source engagement.

I found a route that was locked on `GET` and wide open on `POST`. Same URL, same resource, same handler file, and a single decorator that only covered one of the two functions living inside it. This is a common production bug, it does not need a clever payload to find, and the archive did not have a note behind it yet, so here it is: how method-bound authorization happens, how to recognize a route that has it, and how to test for it without breaking anything.

## Why authorization ends up bound to one verb

Almost every web framework gives you a way to protect a view with a single line: a decorator, a middleware entry, a route guard, something that wraps a handler and redirects or rejects unauthenticated callers before the handler body runs. That pattern works perfectly for the common case of one route, one HTTP method, one function.

It stops working the moment a developer collapses the read and write actions for a resource onto the same route. Frameworks that route by URL rather than by URL-plus-method make this easy to do by accident: you write one view function that branches internally, `if request.method == "GET": render the form` and `if request.method == "POST": save the change`, and you decorate the function once. The decorator wraps the function, not the branch. If the developer wrote the check while thinking about the page load, the "render the form" branch gets tested, works, and looks protected. The `POST` branch was added later, or by someone else, or just was not front of mind when the auth check was written, and it inherits none of the protection because the protection was never applied to it as a distinct thing. The mental model is "this route needs a login," but the code enforces "this handler function, when reached via a browser navigation, needs a login," and nothing forces those two ideas to be the same.

The same failure shows up in API-shaped systems as an asymmetry between the read endpoint and the write endpoint on the same resource path: `GET /resource/edit/<id>` gated behind a session check, `POST /resource/edit/<id>` handled by a different code path (a form-submit handler, a separate blueprint, a legacy function nobody touched during the last auth refactor) that never got the same guard added. Nobody meant to leave the door open. The write path just was not in view when someone wrote the check for the read path.

## Recognizing the condition before you have proof

You will not always be looking at source. From the outside, three signals raise the suspicion that a route's authorization is bound to a method rather than to the resource:

- **A redirect on `GET`, but the route is one you would expect to also accept `POST`.** Anything that looks like an edit form, a settings page, or a create/update action has an implicit write counterpart. If `GET` redirects to a login page, that tells you the read side is gated; it tells you nothing about the write side.
- **The route appears in an `OPTIONS` or `405 Method Not Allowed` response's `Allow` header alongside methods you have not tried.** A `405` on `PUT` that lists `GET, HEAD, POST, OPTIONS` in its `Allow` header is a map: it just told you `POST` is a valid method on this exact URL, whether or not you have tested it yet.
- **The application was clearly built by hand rather than generated from a single declarative permission model.** Frameworks with resource-level authorization built in (a single policy object that governs every verb on a resource) rarely produce this bug. Hand-rolled decorators applied per view function produce it constantly. If you see `@login_required` or an equivalent sitting directly above one function definition rather than attached to a route registration that covers all its methods, treat every other method on that same URL as untested.

None of this requires source access. A directory or endpoint sweep that records status codes across a small set of paths will surface the redirects and the 403s that make a route worth this kind of scrutiny in the first place; a route that is clearly gated on the method you tried first is exactly the kind of route to test again with a different one.

## Testing every verb against a gated route, without breaking anything

The test is cheap and safe to run against a route you already suspect is access-controlled, as long as you are careful about which methods you fire and in what order.

```bash
# baseline: confirm the expected gate on the method you'd normally use
curl -sk -i -X GET "$TARGET/resource/edit/7"
# -> 302 to a login page, or a 401/403: the expected result

# ask the server what it thinks is valid here at all
curl -sk -i -X OPTIONS "$TARGET/resource/edit/7"
curl -sk -i -X PUT "$TARGET/resource/edit/7"
# either response's Allow header lists every method the route accepts

# now try the methods the Allow header named, one at a time
curl -sk -i -X POST "$TARGET/resource/edit/7"
curl -sk -i -X PATCH "$TARGET/resource/edit/7"
curl -sk -i -X DELETE "$TARGET/resource/edit/7"
```

A few rules that keep this from turning into an accidental incident:

- **Never send a state-changing verb (`POST`, `PUT`, `PATCH`, `DELETE`) with a real payload before you know whether it is authorized.** Send it with an empty or minimal body first, purely to read the status code and any redirect. If it returns something other than a redirect or a rejection, you already have your answer without having changed anything: an empty `POST` that returns `200` instead of bouncing to a login page has told you the gate is missing, and only then do you decide whether to send a body that actually demonstrates impact.
- **Read the status code, not just whether it "worked."** A `404` or a `405` is not a bypass, it is the server telling you that verb is not routed here at all. The interesting result is a `200`, or any response that clearly executed application logic (a changed resource, a success message, a flag, a record that appears somewhere it should not) on a verb that is supposed to be gated.
- **Test the paired routes, not just the paired verbs.** The same asymmetry that hides between `GET` and `POST` on one URL also hides between a resource's public view route and its edit route (`GET /resource/7` open, `GET /resource/edit/7` gated is expected; but `POST /resource/edit/7` ungated is the bug). Check both axes: same URL across methods, and sibling URLs for the same resource across the read/write boundary.
- **`HEAD` is not a safe substitute for testing `GET`'s behavior on a write route, and vice versa.** Some frameworks treat `HEAD` as an alias for `GET` automatically; a result there tells you about the framework's routing, not about whether the developer's guard fires. Test the actual verb you care about.

If you find a verb that bypasses the gate, the minimum proof is the pair: the gated request and the ungated request, side by side, against the identical URL.

```bash
curl -sk -i -X GET  "$TARGET/resource/edit/7"   # 302 -> /login   (gated)
curl -sk -i -X POST "$TARGET/resource/edit/7"   # 200             (not gated)
```

That pair is the whole finding. No session token, no injected string, just the right verb sent to a URL that already told you it cared about authorization.

## What the injection stage contributed, generalized

The same engagement had a separate, unrelated bug on its login form: the username field was concatenated directly into a `SELECT` that looked up a stored credential, with no parameterization. That is worth naming for the class it belongs to, without walking through the specific payload chain, since this archive already covers stacked-query SQL injection elsewhere in depth.

The generalizable shape here is different from a stacked query: it is injection into a query whose result is compared against something the attacker also controls. When a login flow works by selecting a stored value and then comparing it to the submitted value in application code, rather than filtering by both fields in the query itself, a single-column `UNION` lets an attacker inject the exact value that comparison will succeed against. The number of columns the query selects tells you how much room you have; probing it (a `UNION SELECT` with an increasing column count until the error goes away) is the first thing to check once a lone quote breaks the query cleanly. Once the column count is known, injecting a chosen literal into that position turns "check my submitted password against whatever is stored" into "check my submitted password against a value I also just supplied," and any password reset or "compare fetched value to submitted value" pattern built the same way is vulnerable to the same trick.

The second contribution was a boolean-blind extraction once that injection point could not directly return data but could still influence which of several application responses came back. The reusable lesson is not the specific extraction script, it is the state model: any blind oracle needs to distinguish at least three outcomes, not two. A naive oracle collapses "condition false" and "query error" into a single negative result, and that collapse produces false negatives whenever a probed value (a table name, a database engine's own version function) does not exist in the schema being tested; a probe for a wrong table name and a probe for a real one that legitimately does not match your guessed condition both come back as errors or empty results for entirely different reasons, and treating them identically sends the search down the wrong branch. Separate true, false, and error as three distinct states before you build any binary search on top of the oracle, or the search will silently mislead itself on exactly the probes meant to fingerprint the target.

## Defensive controls, in order of leverage

- **Enforce authorization at the route registration, not inside the handler.** Bind the guard to every method the route accepts, ideally by attaching it to the resource or the route group rather than to an individual function. If the framework supports a single permission object per resource that governs all its verbs, use that instead of a per-function decorator.
- **Reject unexpected methods explicitly rather than routing them through to application logic by default.** A route that only intends to serve `GET` and `POST` should not silently also execute `PATCH` or `DELETE` logic through a generic handler; an explicit allowlist of methods per route closes off verbs nobody meant to expose at all.
- **Use parameterized queries or prepared statements for every value that reaches SQL, including lookup-only queries that "just" fetch a stored value for comparison.** The root cause on the injection side was string interpolation into a query, not anything special about the login use case.
- **Return one generic error for both failure stages of a credential check** (bad username and bad password should look identical to the caller). A response that distinguishes "unknown identifier" from "identifier found, secret did not match" hands an attacker the two-stage confirmation that speeds up both enumeration and injection probing.
- **Log and alert on state-changing verbs hitting routes that are also gated on `GET`,** especially any that succeed without an active session. A single unauthenticated `POST` reaching an edit handler is a strong signal on its own, independent of whether a human ever notices the missing decorator in code review.

## Reusable checklist

- Any route that redirects or rejects on `GET` gets tested again on `POST`, `PUT`, `PATCH`, and `DELETE` before you conclude it is protected.
- Read the `Allow` header from an `OPTIONS` or a `405` response before guessing which methods to try; it tells you what the server considers valid on that exact URL.
- Send state-changing verbs with an empty or minimal body first. A `200` where you expected a redirect is the finding, before you ever construct a payload.
- Check both axes: same URL across methods, and a resource's read route versus its sibling write route.
- Treat a hand-rolled `@decorator`-per-function pattern as a standing reason to distrust every other verb on that URL, even after one verb tests clean.
- In any blind injection oracle, keep true, false, and error as three separate states. Collapsing error into false produces confident wrong answers on exactly the schema probes you need most.
- A login or reset flow that fetches a stored value and compares it in application code, rather than filtering by both fields in the query, is a UNION target the moment a lone quote breaks it.

## Closing

Nothing about this bug required a hard payload. The access control failure was found by asking one more question of a route that had already answered the first one: it says no to `GET`, does it say no to everything else too. The injection was found the same way, by comparing what two nearly identical inputs produced and trusting the difference. Both come from the same habit: when a system tells you it checked something, verify it checked all of it, not just the path you happened to test first.
