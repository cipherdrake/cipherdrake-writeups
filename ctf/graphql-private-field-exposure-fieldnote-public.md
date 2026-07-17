---
title: "The Sibling Type That Leaks: GraphQL Private-Field Exposure and the Unenforced Boolean"
date: 2026-06-18
tags: [appsec, ctf, graphql, idor, bola, broken-access-control, introspection, methodology]
status: draft (neutral / voice-agnostic; recast into article voice before publishing)
sanitized: true (no target identity, platform, endpoints, operation names, ids, or real flag)
visibility: public
---

# The Sibling Type That Leaks: GraphQL Private-Field Exposure and the Unenforced Boolean

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere. No real target, platform, endpoints, ids, or flag values.

On a GraphQL target the schema is the recon. When introspection is on, the type system is handed to you, and authorization bugs show up as asymmetries you can read off the types before you touch a single byte of data. Here is the cleanest version of that: two near-identical object types where one carries a sensitive field its sibling omits, and a `private` boolean that the API returns but never enforces.

## The shape of the target

A read-only GraphQL API (no mutations) with introspection enabled. The schema models the same underlying object two ways:

- A **public listing** returns a collection of objects through a type that *omits* the sensitive field.
- A **per-owner path**, reached by walking a relationship edge from a user to that user's objects, returns a near-identical type that *includes* the sensitive field.

A boolean like `private: true` marks the records that are supposed to be protected. Nothing enforces it.

## Reading the schema: the field delta is the bug

Dump the type system and look, in order, for:

1. **`mutationType`.** Null means read-only; the whole surface is the read side.
2. **Sibling types that differ by exactly one field.** This is the highest-signal tell. When two types model the same object and one carries the sensitive field (`text`, `email`, `notes`, `secret`) while the other does not, the field-less one is the decoy that lulls you on the public listing, and the other is the real read path.
3. **Sensitive field names** anywhere, and which queries or edges reach the types that hold them.
4. **Boolean "control" fields** (`private`, `hidden`, `published`). A boolean is only a control if a resolver enforces it. If the API returns `private: true` and *also* returns the protected field, the boolean is decoration, not authorization.
5. **The reachability graph**: which root field reaches which type, and which relationship edge reaches a type the hardened root field tries to hide.

Here the public listing type omits the sensitive field, but the type reached through the user-to-objects edge includes it, and the resolver returns it without checking the record's `private` flag. The asymmetry is the entire vulnerability.

## The proof: locate without spoiling

You can confirm the gap with metadata alone. Walk from the users collection into each user's objects and request the id and `private` flag, not the sensitive field. A record marked `private: true` that the per-owner path is willing to return at all is the target; the sensitive field on that node is the protected data.

```graphql
{ allUsers { edges { node {
  username
  things { edges { node { id private } } }
} } } }
```

If the metadata reads out for a record you should not be able to see, the sensitive field will too, through the same path. The protected read is the same query with the sensitive field added.

## Why it happens: hiding a field on one type is not authorization

Two failures stacked:

- **The data was modeled as two parallel types**, one of which happens to omit the sensitive field. Sibling types drift, and one of them always ends up leaking the field the other hides. The fix is one type with an authorized resolver on the sensitive field, not two types that differ by which fields they expose.
- **The `private` boolean is returned but never checked.** Reading the sensitive field has to verify the requester owns the record (or is privileged), regardless of which type or path reaches it.

The portable mental model: a sensitive field is only as protected as the *least-guarded type that exposes it*. Authorization belongs in the resolver that returns the field, applied on every path, not in the choice of which listing type happens to omit it.

## Reusable checklist

- Introspection on? Read the type system before the data.
- Diff sibling types. Two types modeling the same object that differ by one sensitive field is the tell; the safe-looking listing type is the decoy.
- Treat every `private`/`hidden`/`isAdmin` boolean the API will *show* you as a thing to test for whether it is *enforced*.
- Test every path to the same object, not just the obvious one. A hardened root field is routinely undone by the same object reached through a relationship edge.
- Confirm with metadata first (id + the boolean), so you locate the protected record without reading it.

## Closing

No injection, no fuzzing. The win was reading the schema, noticing one type carried a field its sibling did not, and recognizing that a returned-but-unenforced boolean is an access-control gap. Map the type system first; the asymmetries point straight at the bug. Sometimes the deliverable is the method.
