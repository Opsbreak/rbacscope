# Security Policy

## Supported versions

Security fixes are released for the latest minor version of rbacscope.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a vulnerability

Please do **not** open a public GitHub issue for security problems.

Report vulnerabilities privately through either channel:

- GitHub private vulnerability reporting: the **"Report a vulnerability"** button
  under the repository's **Security** tab
  (https://github.com/Opsbreak/rbacscope/security/advisories/new), or
- email **admin@opsbreak.com**.

Please include the rbacscope version, a description of the issue, and a minimal
set of manifests or steps that reproduce it. Do not send real cluster exports
that contain secrets or customer data; redact or synthesise them.

## What to expect

- We acknowledge reports within **3 business days**.
- We will confirm the issue, assess impact, and keep you informed of progress.
- We follow **coordinated disclosure**: we agree a disclosure date with you,
  publish a fix and a GitHub Security Advisory, and credit you unless you
  prefer to remain anonymous.

## Scope

In scope: incorrect analysis that hides real privilege-escalation risk (false
negatives in the authorizer model, audit rules or path search), crashes or
resource exhaustion on crafted manifests, and anything that could cause
rbacscope to leak data it reads (for example Secret contents).

rbacscope is an offline analyzer. It does not connect to clusters and never
decodes Secret `data`/`stringData` fields.
