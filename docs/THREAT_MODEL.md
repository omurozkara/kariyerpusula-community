# Threat model — Evidence Policy v0.1.0

This document is a **reference threat model**, not certification or proof of a production deployment.

## Assets and trust boundaries

- **Assets:** complaint evidence, user identity, tenant ownership, document object keys, signed download URLs and test credentials.
- **Trusted sources:** independently authenticated server identity, checked resource owner/tenant and server-side permission grants.
- **Untrusted sources:** HTTP parameters, client role fields, object keys provided by users, uploaded filenames, claimed MIME types and any arbitrary document bytes.

## Threats and mitigations

| Threat | Library capability | Application responsibility |
| --- | --- | --- |
| Object enumeration | 128-bit random file keys | Private buckets, authorization, access logs and rate limits |
| Path traversal | Strict key grammar | Normalize and constrain storage paths and resource IDs |
| IDOR / horizontal access | Fail-closed owner/role policy helper | Fetch resource ownership server-side; test tenant boundaries |
| Role spoofing | Documented trusted-role contract | Never accept role directly from request body or browser |
| File-type masquerading | Basic magic bytes | Full validation, malware scanning, size limits, content transformation |
| Link leakage | No public URL helper | Short-lived signed URLs, no-referrer headers, revoke on permission changes |
| Accidental destructive test | Loopback-only E2E target guard | Dedicated test database/storage and environment/project identity checks |
| Sensitive metadata leak | Random names avoid client filenames | Minimize API responses; redact logs; retention/deletion controls |

## Non-goals

This package does not authenticate, cryptographically sign URLs, enforce database row-level security, operate storage, detect viruses or provide legal compliance. Attackers may guess already-known object URLs only if the application exposes them; random object names alone are not an access-control mechanism.

## Security regression cases before production use

- Unauthorized owner/role/grant and anonymous access attempts
- Tenant-crossing objects and revoked grants
- Public bucket misconfiguration and object ID enumeration
- Unexpected file types, malformed headers and malicious documents
- Expired/replayed signed links and cache propagation after deletion
- Real PII never appearing in browser responses, issue reports or logs
