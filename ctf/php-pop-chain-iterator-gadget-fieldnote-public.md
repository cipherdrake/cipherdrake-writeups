---
title: "The Gadget Isn't Always a Magic Method: PHP Object Injection via Implicit Interface Calls"
author: CipherDrake
date: "2026-07-29"
visibility: "public"
tags:
  - ctf
  - web
  - php
  - deserialization
  - pop-chain
  - cwe-502
  - gadget-chain
---

# The Gadget Isn't Always a Magic Method: PHP Object Injection via Implicit Interface Calls

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

A small PHP web application had an order-submission endpoint that base64-decoded a POST parameter and passed it straight into `unserialize()`. This is a classic PHP object injection (POP chain) setup, but the actual gadget that fired the payload was not one of the usual `__`-prefixed magic methods everyone checks for first. It was a plain interface method PHP calls without any special naming convention at all. That gap between "the gadgets I know to grep for" and "the gadgets that actually exist" is the whole lesson.

## The setup

The application shipped its own source (no framework, no `vendor/` dependency tree), which matters for how a POP chain gets built: with no third-party library in play, there is no public gadget-chain tool to reach for. The entire gadget space is whatever classes the application itself defines. Here that was a small, fully enumerable set of custom classes.

An initial pass over the source for magic methods (`__destruct`, `__wakeup`, `__toString`, `__get`, `__invoke`, `__call`, and similar) turned up three candidates across three classes:

- Class **A** ("Entry"), with a `__destruct()` method.
- Class **B** ("Pivot"), with a `__get()` method.
- Class **C** ("Invoker"), with an `__invoke()` method.

That looks like a complete gadget chain on its own: `__destruct` fires automatically on any object built by `unserialize()`, without any application cooperation, which is why it is the standard entry point for a POP chain. From there the classes chained naturally: the destructor read an undefined property on another deserialized object, which triggered that class's `__get()`; the getter treated a third deserialized object as a callable, `($this->property)()`, which triggered that class's `__invoke()`.

## Where the actual sink was hiding

The chain didn't stop there. `__invoke()` looped over a fourth deserialized object with `foreach`. That object was an instance of a helper class extending PHP's built-in `ArrayIterator`, and it overrode `current()`:

```php
class Helper extends ArrayIterator {
    public function current() {
        $value = parent::current();
        $callback = $this->callback;   // attacker-controlled
        call_user_func($callback, $value);
        return $value;
    }
}
```

`current()` is not a magic method. It has no double underscore, and it will not show up in a grep for `__`. But `foreach` over any object implementing PHP's `Iterator` interface calls `current()` (along with `next()`, `valid()`, `rewind()`, `key()`) on every step of the loop, implicitly, as part of the language's iteration contract. Overriding it on a class an attacker can instantiate via `unserialize()` is exactly as dangerous as overriding `__toString` -- it's just invisible to a search that only looks for the underscore-prefixed family.

This generalizes past `Iterator`. Any interface PHP invokes implicitly on an object is a place a gadget can hide:

- `Iterator` -- `current()`, `next()`, `valid()`, `rewind()`, `key()` (called by `foreach`)
- `ArrayAccess` -- `offsetGet()`, `offsetSet()`, `offsetExists()`, `offsetUnset()` (called by `$obj[$key]` syntax)
- `Countable` -- `count()` (called by `count($obj)`)
- `IteratorAggregate` -- `getIterator()` (called by `foreach` when this interface is used instead of `Iterator`)

A class extending a built-in SPL container (`ArrayIterator`, `ArrayObject`, `SplObjectStorage`, and similar) and overriding one of these methods is a gadget candidate in exactly the same sense as a class defining `__wakeup`. A POP-chain audit that stops at the magic-method roster will map the entry point and the pivots correctly and then walk right past the payoff.

## The second widening: variable function calls

The pivot step deserves its own note. The `__get()` method's payload was `($this->property)()` -- a *variable function call*. PHP does not restrict this syntax to actual named functions. Anything that qualifies as a PHP "callable" works:

- A string: `'system'`, `'phpinfo'`, `'exec'`.
- An array pointing at an instance method: `[$object, 'methodName']`.
- An array pointing at a static method: `['ClassName', 'staticMethodName']`.

Once a chain reaches an expression of this shape, the reachable surface is every zero-argument method on every loaded class in the application, not just whichever magic methods an initial `__`-grep happened to surface. The magic methods get a chain *moving*; a variable function call (or any call to `call_user_func()`/`call_user_func_array()` with an attacker-controlled first argument) is what actually reaches arbitrary code. In this case, the overridden `current()` itself called `call_user_func($callback, $value)` with both the callback name and the value fully attacker-controlled -- setting the callback to a command-execution function turned the deserialization bug into remote code execution.

## Why this matters beyond one challenge

The practical takeaway for auditing (or building) a PHP POP chain:

1. Enumerate every `__`-prefixed magic method first -- that's still where the entry gadget (`__destruct`, usually) and most pivots live.
2. Then separately enumerate every class that extends an SPL container or implements `Iterator`, `ArrayAccess`, `Countable`, or `IteratorAggregate` and overrides one of those interface's methods. These are gadgets too, invoked implicitly by ordinary language constructs (`foreach`, `$obj[$key]`, `count($obj)`) rather than by any special naming convention.
3. Once a chain reaches a variable function call or a `call_user_func()`/`call_user_func_array()` invocation with attacker influence over the callable argument, treat the gadget space as "every zero-argument method in the application," not just the methods already identified.

A supporting practical lesson from the same engagement: serialized-object payloads are PHP-version-sensitive in ways that are easy to get backwards from memory (exact format details around the SPL classes and the `Serializable` interface changed across PHP releases). Don't trust a remembered cutoff for which serialization format a given PHP version produces -- generate the payload on (or against) the actual target runtime and diff the output, rather than asserting the format from recall.

## Defensive controls

- Never call `unserialize()` on data that can originate from a client -- a cookie, a POST body, a cache value, anything crossing a trust boundary.
- Prefer JSON (`json_decode`/`json_encode`) for any data that needs to survive a round trip across that boundary. JSON carries no object-instantiation capability.
- If native serialization is unavoidable, always pass the `allowed_classes` option to `unserialize()` -- either `false` (no objects at all) or an explicit allowlist of the only classes that should ever be instantiated this way. This single control breaks every chain of this shape, because none of the gadget classes would be permitted to instantiate from untrusted input.
- Keep dangerous dynamic-dispatch sinks (`call_user_func`, `call_user_func_array`, any variable function call) away from any class whose properties can be populated from a deserialized, attacker-shaped object graph.
- If a serialized envelope must cross a trust boundary at all, sign or HMAC it so tampering is detectable before `unserialize()` ever touches it.

The general shape of the bug -- and the fix -- is identical to a Python pickle deserialization bug or a Java/.NET gadget chain: never deserialize untrusted data into a live object graph without either restricting what can be instantiated or verifying integrity first. PHP's specific twist is that the vulnerable "gadget" surface is wider than most people assume, because the language calls plenty of methods implicitly that have nothing to do with the `__` naming convention.
