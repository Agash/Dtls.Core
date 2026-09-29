# Security Policy

## Supported versions

Only the latest released version of Dtls.NET receives security fixes. This project is pre-1.0, so
fixes land on the current minor rather than being backported.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub Security Advisories:

1. Go to the [Security tab](../../security/advisories/new) of this repository.
2. Choose **Report a vulnerability**.
3. Describe the issue, the affected version, and how to reproduce it.

You should get an acknowledgement within a few days. Once the issue is confirmed, a fix will be
prepared privately and released together with an advisory crediting you, unless you would rather
stay anonymous.

## Scope

Dtls.NET is a security protocol implementation, so almost any defect can be a vulnerability: a
handshake that accepts what it should refuse, a record that decrypts or authenticates when it should
not, a parser that reads out of bounds or can be made to allocate without limit, key material that
outlives its use, or timing that depends on secret data. All of these are in scope. Weaknesses in the
.NET cryptographic primitives themselves belong to the .NET runtime.
