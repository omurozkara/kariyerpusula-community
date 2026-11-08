# KariyerPusula Community — Evidence Policy

A small, **MIT-licensed**, zero-runtime-dependency Node.js utility for privacy-conscious evidence handling. This is an independently authored example extracted from the *problem domain* of KariyerPusula, **not** copied from the private commercial repository or its Git history.

It provides secure random object keys, key-format checks, a narrow access-policy helper, magic-byte identification for supported file types, and a loopback-only E2E target guard. It is useful for moderation, grievance and application workflows where evidence and documents must not be public by default.

**Maturity:** experimental v0.1.0. No download or adoption statistics are claimed. Not yet published to npm.

## Try it

Requires Node.js 20+. Run `npm test` (built-in Node test runner, no network install). The import example below is for a local repository checkout, not an npm-installed package.

```js
import {
  createEvidenceKey, canAccessEvidence, matchesEvidenceSignature,
} from './src/index.mjs'; // local clone; package is not on npm yet

const objectPath = createEvidenceKey('complaint_123', 'application/pdf');
const authorized = canAccessEvidence({
  viewerId: authenticatedUser.id,
  ownerId: serverLoadedComplaint.authorId,
  role: authenticatedUser.role,
});
if (!authorized) throw new Error('Forbidden');

// The storage SDK must use a PRIVATE bucket; do not return `getPublicUrl()`.
// Create an expiring signed URL only AFTER server-side authorization.
```

Example above is illustrative: `authenticatedUser` and `serverLoadedComplaint` must come from trusted server-side sources. `canAccessEvidence` **does not authenticate a user** and must never be called with client-controlled role/owner data.

## API

| Export | Purpose |
| --- | --- |
| `createEvidenceKey(id, mime)` | Randomized storage key without exposing the uploaded name |
| `validateEvidenceKey(key)` | Strictly validate an object-key format, rejecting URLs and traversal |
| `canAccessEvidence(policy)` | Fail-closed owner/moderator/admin access check |
| `matchesEvidenceSignature(bytes, mime)` | Basic file magic-byte recognition |
| `assertLocalTestTarget(url)` | Block tests aimed at remote hosts |

## Threat model and limitations

- This library does **not** enforce authentication, database ownership, permissions granted by a real company, auditing, RLS, object storage policies, malware detection, content disarm, DLP, rate limiting, CSRF protection, encryption, secure deletion, or consent compliance.
- Magic-byte recognition is a **weak preliminary control**, not proof a file is safe. Add complete file validation and malware scanning according to your application risk.
- Cryptographically random names do not make a public bucket private. **Use private storage and short-lived links.**
- Production-grade access control needs object-by-object authorization against your database and integration tests, including tenant separation, anonymous users and revoked grants.

## Repository structure

```
src/index.mjs         Pure Node.js implementation
src/index.d.mts       Types for TS consumers
test/                 Node built-in tests
.github/workflows/    CI
```

## Project governance and maintenance

- **Maintainer:** Ömür Deniz Özkara (`@omurozkara`)
- **Version:** `0.1.0` experimental; security response times and release cadence are not promised.
- **Contributing:** see [CONTRIBUTING.md](CONTRIBUTING.md); security reports follow [SECURITY.md](SECURITY.md).
- **Threat model:** see [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
- **Changes:** see [CHANGELOG.md](CHANGELOG.md).

## Community and roadmap

We welcome constructive issues, tests, portable API improvements and threat-model feedback. Planned: adapter examples for private S3/Supabase buckets, explicit audit hooks, TypeScript integration checks, revocation scenarios. No other contributors or users are yet claimed.

The commercial **KariyerPusula Core** is maintained privately; the **community utility is separate**. A code license does not grant trademark rights to the KariyerPusula brand.

## License

MIT. See [LICENSE](LICENSE).
