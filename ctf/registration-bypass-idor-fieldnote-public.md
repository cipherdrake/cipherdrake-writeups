---
title: "Two API Authorization Gaps That Chain: Registration Bypass via Unauthenticated Endpoint + File Listing IDOR"
date: 2026-07-10
tags: [appsec, ctf, idor, broken-access-control, api-security, openapi, owasp-api-top-10, methodology]
status: complete
sanitized: true
visibility: public
---

# Two API Authorization Gaps That Chain: Registration Bypass via Unauthenticated Endpoint + File Listing IDOR

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere. No real target, platform, endpoint names, parameter names, credentials, flags, vendor names, or verbatim error strings.

Two unrelated authorization gaps, one file download. Neither gap is exotic. Both are configuration choices that look correct during development and become attack surface the moment the application faces an adversary.

## The setup

A web application with user accounts and per-user file storage. Registration is open, but accounts require email verification before login is allowed. Email is handled server-side -- there is no way to receive the verification email from outside the system.

The API was built with a framework that auto-generates endpoint documentation from the code. That documentation, once found, told the whole story.

## Finding the documentation

The application's API framework mounts its auto-generated documentation at a path that matches the API's base URL prefix -- not necessarily the root. Checking the root-level documentation paths manually returned 404 on every attempt. A wordlist scan against the API prefix found the documentation endpoints within seconds.

This is the load-bearing workflow lesson: **check for the auto-generated spec before brute-forcing anything.** Modern API frameworks (the category, not any specific one) routinely ship interactive documentation that lists every endpoint, every request and response schema, and every declared authentication requirement. That documentation is discoverable with a wordlist if you look in the right place. The spec is the endpoint map, and it costs one scan to find.

## Reading the security annotations

The spec listed every endpoint in the application. Every endpoint carried a declared authentication requirement -- except one.

In the OpenAPI standard, a `security` annotation on an endpoint declares what authentication is required. An absent annotation, when no global default is set, means no authentication is required. One endpoint in this application had no annotation while every other endpoint required a bearer token. That endpoint was the anomaly to test.

The anomaly was a "user details" lookup that accepted an email address and returned the corresponding user's full database record. The record included a verification token -- the same long, unpredictable string the application would normally send by email to confirm account ownership.

No authentication required. Any caller. Any email address.

## The bypass

One request to the unauthenticated endpoint, supplying my own account's email address, returned my account's full record including the verification token. I submitted the token to the verification endpoint, the account became active, and login succeeded.

The fix is not to hide the endpoint. Hidden endpoints are not protected endpoints. The fix is to require authentication on every endpoint that returns user data -- including endpoints whose response schemas include values the server relies on for security decisions. A verification token is a credential. It belongs behind the same authentication requirement as everything else that matters.

## The file listing IDOR

With a valid session token, I requested my file listing. The response included files belonging to other users.

The response schema included an ownership field on every record -- identifying which user each file belonged to. That field was not used as a filter at the database layer. The query returned every file in the system and returned them all to any authenticated caller.

The ownership field in the response is not access control. It is metadata. Server-side scoping -- filtering the query to records where the ownership field matches the authenticated caller's identity -- is the actual control. Client-side display logic that hides other users' files from the UI is not a substitute; any caller who bypasses the UI and sends a direct API request receives everything.

One file in the listing belonged to another user and contained the target content. One download request retrieved it.

## The workflow observation

The 30 minutes spent attempting to brute-force the verification token were wasted. The token was not brutable -- its format was a long unpredictable identifier, not a short numeric code. The spec, which I found after the brute force was abandoned, confirmed the format immediately.

**When a brute-force attempt produces errors or crawls at low thread counts: confirm the token format before assuming the server is the bottleneck.** A six-digit numeric code and a 128-bit random token require entirely different approaches. The spec or source review answers the format question in under a minute. Wordlists built on wrong format assumptions waste the session.

## What to check on any API target

- Find the API framework's auto-generated documentation. The prefix matters -- look where the API lives, not just at the root.
- Read the security annotations in the spec. Any endpoint without a declared authentication requirement is the first thing to test, regardless of what it appears to do.
- For every response schema that includes an ownership or user-identity field in a collection endpoint: test whether the server actually uses that field as a filter, or whether it returns all records.
- Check which fields in a user record the application relies on for security decisions. Those fields do not belong in any unauthenticated response.

The authentication check and the access control scope are separate controls. Both need to be present. An endpoint can require authentication and still return the wrong data; a field in the response schema is not a WHERE clause.
