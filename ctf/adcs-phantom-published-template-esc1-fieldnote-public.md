---
title: "Phantom Published Templates: How a CA's Own Template List Becomes an ESC1 Primitive"
author: CipherDrake
date: "2026-08-14"
category: field-note
visibility: public
tags:
  - adcs
  - active-directory
  - esc1
  - certificate-templates
  - privilege-escalation
  - field-note
---

# Phantom Published Templates: How a CA's Own Template List Becomes an ESC1 Primitive

> **VISIBILITY: PUBLIC.** Sanitized; safe to post anywhere.

## The setup

An Active Directory Certificate Services (AD CS) deployment has two related but distinct data
structures: the list of template names a Certification Authority (CA) has "published" (the
`certificateTemplates` attribute on the CA object), and the actual template objects that live in
the Certificate Templates container in the Configuration partition. Under normal operation, every
published name has a matching object, because publishing a template is supposed to be the last
step after the object is created and hardened.

That assumption is not enforced anywhere. A CA can publish a name with no backing object at all,
and nothing in AD CS stops it or flags it as unusual. If that happens (a provisioning script run
out of order, a template deleted without being unpublished, a staged deployment interrupted
partway), the CA is left advertising a certificate type it cannot currently issue.

## The primitive

Advertising a name with no object is not exploitable by itself. What makes it exploitable is a
second, independent condition: a low-privileged principal holding `CreateChild` on the Certificate
Templates container itself, rather than write rights on any specific template object.

Combine the two and the attack is direct: create a new object in the container using the exact
name the CA already has published, give it standard ESC1 characteristics
(`msPKI-Certificate-Name-Flag` including `ENROLLEE_SUPPLIES_SUBJECT`, no manager approval,
a client-authentication EKU, a low key-size floor), and the CA treats it as immediately valid.
There is no separate "publish" step to bypass, because the name is already published. There is no
`ManageCA` right required, because creating an object in the container is a container-level ACL,
not a CA-configuration action. The object springs into existence already trusted by the name the
CA was already advertising.

This is a variant of the ESC4 family (template misconfiguration abused by a principal who can
write to the PKI object graph), but it is creation rather than modification, and it does not show
up in standard tooling's default vulnerable-template scan, because that scan enumerates existing
template objects. A phantom has no object to enumerate until you make one.

## How to recognize it

1. Enumerate the CA's published template list (its `certificateTemplates` attribute) and,
   separately, every actual template object in the Certificate Templates container.
2. Diff the two lists. Any name present in the CA's published list with no matching template
   object is a phantom.
3. Check the ACL on the Certificate Templates container itself, not on any individual template.
   Look specifically for `CreateChild` (object-create rights) held by a non-PKI-admin principal or
   group.
4. If both conditions hold (a phantom name exists, and you hold `CreateChild` on the container),
   you have a live ESC1-equivalent primitive without needing write access to any existing
   template and without needing CA-management rights.

A useful confirming signal along the way: requesting a certificate against the phantom name
*before* creating anything typically returns a distinct error (something like "unsupported
certificate type") rather than the error you'd get from requesting a name the CA has never heard
of at all, or the error you'd get from a template that exists but denies your enrollment. That
distinct error is the tell that the CA recognizes the name but has nothing behind it.

## Why this is easy to miss

Most ESC-family hunting checklists (and most automated tooling) are built around "does an
existing template have a dangerous configuration or a dangerous ACL." A pre-published phantom
inverts the question: the dangerous configuration doesn't exist yet, and won't, until an attacker
with the right container-level right creates it. Reviewers who only check existing template
objects, and tooling that only enumerates existing template objects, will both report a clean CA.

A related trap worth flagging separately, because it cost real time on the engagement this note
is drawn from: a certificate-officer-shaped right (the ability to approve or force-issue a denied
certificate request, sometimes called `ManageCertificates`) looks like it should complete an ESC7
attack, but it is frequently more restricted than it appears. `ManageCertificates` alone typically
cannot force-issue a request that was denied at the template-enrollment level; that generally
requires the broader `ManageCA` right. Don't assume a certificate-officer role is a complete ESC7
path until you've confirmed it can actually move a denied request to issued, not just that it
exists.

## Illustrative example (not the real values)

```text
CA published templates:  User, Machine, WebServer, SubCA, CustomVpnTemplate
Enumerated template objects: User, Machine, WebServer, SubCA
  -> "CustomVpnTemplate" is a phantom: published, no backing object

Certificate Templates container ACL:
  (A;;0x20015;;;S-1-5-21-...-XXXX) = READ_CONTROL + READ_PROP + LIST + CREATE_CHILD
  -> a non-admin group holds CreateChild on the container

Action: create CN=CustomVpnTemplate,CN=Certificate Templates,... as a new
pKICertificateTemplate object, ENROLLEE_SUPPLIES_SUBJECT=1, no manager approval,
Client Authentication EKU, enroll ACL granted to the requesting principal (who is
CREATOR OWNER on the new object and can set its own DACL).

Result: immediately enrollable, no ManageCA and no separate CA publish step needed.
```

## A second control worth naming while we're here

Even a correctly-configured ESC1 template will fail to authenticate via PKINIT on a
fully patched, modern domain controller if the certificate request only carries a UPN in the
Subject Alternative Name. Since the rollout of strong certificate mapping enforcement
(the "KB5014754" class of update), the domain controller expects the target principal's SID to be
present in the certificate's security extension. A request built with only a UPN will typically
fail with an object-SID-mismatch error at authentication time, even though the certificate itself
issued successfully. This is not a bug in the exploit chain; it's a real control doing its job,
and any modern ESC1/ESC-family enrollment needs to explicitly request the SID extension to
succeed against a hardened DC. Worth remembering as a defensive win, not just an offensive
workaround: environments that have not yet enforced strong mapping are meaningfully weaker here.

## Defensive takeaways

- Diff your CA's published-template list against your actual template objects on a schedule.
  A published name with no object is not neutral; it is a standing primitive waiting for the
  right ACL to exist somewhere in your environment.
- Restrict `CreateChild` on the Certificate Templates container to a dedicated PKI-administration
  group. No help-desk, DevOps, or general-IT group should be able to create objects in that
  container, independent of what rights they hold on any individual template.
- Never publish a template name on a CA before the corresponding object exists and has been
  reviewed. Treat "publish" as the last step of a change process, not an early-provisioning
  convenience.
- Confirm strong certificate mapping enforcement is fully enabled in your environment, and audit
  any enrollment workflow that issues certificates without embedding the target principal's SID.
- Periodically review which groups hold certificate-officer-shaped rights (`ManageCertificates`)
  versus full CA-management rights (`ManageCA`). A support-tier or delegated-admin group holding
  either is worth a second look regardless of whether it can be immediately weaponized end to end.

## The portable lesson

Vulnerable-template scanners answer "is anything currently misconfigured." They do not answer
"can a low-privileged principal create something misconfigured that the CA will trust
immediately." Those are different questions, and AD CS environments should be audited for both:
what exists today, and what a `CreateChild` right on the templates container (or any other
object-creation right in the PKI object graph) would let someone create tomorrow.
