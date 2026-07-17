---
title: "Hidden Is Not Protected: Relay node(id:) IDOR and the Listing-Filter Illusion"
date: 2026-06-18
tags: [appsec, ctf, graphql, idor, bola, broken-access-control, relay, methodology]
status: draft (neutral / voice-agnostic; recast into article voice before publishing)
sanitized: true (no target identity, platform, endpoints, operation names, ids, or real flag)
visibility: public
---

# Hidden Is Not Protected: Relay node(id:) IDOR and the Listing-Filter Illusion

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere. No real target, platform, endpoints, ids, or flag values.

A common "fix" for a leaking record is to stop returning it from the listing query. The record vanishes from the obvious read path, the bug report is closed, everyone moves on. The record is still there, and on a Relay-style GraphQL API it is almost always still readable by id. Hiding an object from a listing is not access control. This is the pattern, how to test it in three queries, and why it keeps happening.

## The shape of the target

A GraphQL API with introspection on. The schema exposes a few read paths to the same object type: a listing query that returns a collection, a named lookup, and the Relay global fetcher `node(id:)` on the query root. There is also a write surface (a mutation that edits the object). No authentication required, or authentication that does not gate the object read.

The collection listing returns only the records you are "supposed" to see. One sensitive record carries a boolean like `private: true` and is absent from that listing. That absence is the entire defense.

## Why introspection plus a forgeable id is the recon

When introspection is enabled, read the type system before touching data. The schema hands you the data model: which types carry the sensitive field, and which root fields and relationship edges reach those types. Most GraphQL bugs are authorization bugs, and authorization bugs show up as a path to an object that skips the check the obvious path enforces.

Relay global ids are opaque, but they are almost always base64 of `"<TypeName>:<integer>"`. Decode one legitimate id and you know the encoding for all of them.

```
# a record id from the listing, base64-decoded (illustrative values):
VGhpbmc6MQ==   ->   Thing:1
```

Once the encoding is known, you can forge the id of an object you were never shown: change the integer, re-encode, and feed it to anything that takes an id.

```
btoa("Thing:2")   ->   VGhpbmc6Mg==
```

## The test: three queries

1. **List what you are allowed to see, and decode the ids.** Note which records appear and which boolean flags they carry. A near-sequential id space tells you exactly which ids exist but are missing from the listing. That gap is the target.

2. **Confirm the hidden record exists, metadata only.** Forge the next id and hand it to `node(id:)`. Because `node` returns the `Node` interface, use an inline fragment to pull concrete fields. Request the id and the `private` flag, not the sensitive field yet.

   ```graphql
   { node(id: "VGhpbmc6Mg==") { ... on Thing { id private } } }
   ```

   If it comes back with `private: true`, you have just resolved a record that appears in no listing, by forging an id the UI never showed you. That is the IDOR primitive.

3. **Capture: request the sensitive field on the same forged id.** If the read is not gated, the protected field reads straight out.

   ```graphql
   { node(id: "VGhpbmc6Mg==") { ... on Thing { id private secretField } } }
   ```

   No authentication, no mutation, one query.

## The decoy: do not reach for the write surface first

When the schema adds a shiny new mutation that edits the object, it is tempting to treat that as the intended path: call the mutation on a record you do not own, and if its response echoes the object back (`{ ok, object { secretField } }`), you read the protected field off the mutation result. That works, and it is a real broken-authorization finding (no ownership check on the id argument). But it usually *writes* first, clobbering the object's data, and it is louder and riskier than necessary.

Enumerate the read paths before the write paths. A read-side `node(id:)` IDOR gets the same data with a single non-mutating query. On a live target, a destructive proof when a non-destructive one exists is a mistake, not thoroughness.

## Why it held together wrong: the check belongs on the resolver

The lesson under the lesson: an object is only as protected as the *least-guarded path that reaches it*. Removing a record from a listing changes one resolver. It does nothing to the `node(id:)` resolver, the named-lookup resolver, or the mutation that returns the same object. Each of those is a separate door, and authorization has to be enforced at each one.

For a defender: object-level authorization lives in the resolver that returns the object, checked against the authenticated principal, for every path that resolves that type, including the generic `node(id:)` interface and any mutation that echoes the object in its response. Hiding the object from one listing, randomizing ids, or disabling introspection are defense-in-depth at best. The control is the per-object check.

For a hunter: "the record is hidden from the listing" is a lead, not a closed door. "The id is forgeable" is a lead, not a finding. The finding is the missing check on the by-id path, and `node(id:)` is where it most often goes missing because teams authorize the named queries and forget the generic fetcher.

## Reusable checklist

- Introspection on? Read the type system first. Find every path that reaches the sensitive type (listing, named lookup, `node(id:)`, mutation response).
- Decode one real global id. If it is base64 `Type:integer`, the id space is forgeable and probably enumerable.
- List what you can see, then look for the gap: an id that must exist but is absent from the listing.
- Forge the gap id, confirm the record with `node(id:)` metadata only, then request the sensitive field.
- `node(id:)` is the GraphQL IDOR primitive. Test it before the named queries; it skips per-type authz most often.
- Prefer the non-destructive read path. A mutation that echoes the object is a read in disguise, but it writes first; use it only when no read path reaches the object.
- A record hidden from a listing is not protected. Always test direct fetch-by-id.

## Closing

The whole break was recognition, not a payload: introspect, see that a record was pulled from the listing but left reachable by a forgeable global id, and fetch it directly. The "fix" was security by obscurity, and the generic `node(id:)` fetcher walked right around it. On any Relay-style GraphQL schema, decode an id and try fetch-by-id before anything else. Sometimes the deliverable is the method.
