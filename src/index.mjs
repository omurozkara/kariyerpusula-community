import { randomBytes } from 'node:crypto';

/**
 * Policy-only utilities. The application is responsible for authentication,
 * verifying membership/ownership on the server, private storage and auditing.
 */
export const ALLOWED_MIME = Object.freeze({
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp',
  'application/pdf': 'pdf',
});

/** Do not derive object keys from client-provided file names. */
export function createEvidenceKey(resourceId, mime) {
  if (typeof resourceId !== 'string' || !/^[A-Za-z0-9_-]{1,100}$/.test(resourceId)) {
    throw new TypeError('Invalid resource identifier');
  }
  if (!Object.hasOwn(ALLOWED_MIME, mime)) {
    throw new TypeError('Unsupported MIME type');
  }
  return `${resourceId}/${randomBytes(16).toString('hex')}.${ALLOWED_MIME[mime]}`;
}

/** Validate only the storage key shape: never accept URLs or traversal. */
export function validateEvidenceKey(key) {
  if (typeof key !== 'string') return false;
  return /^[A-Za-z0-9_-]{1,100}\/[0-9a-f]{32}\.(?:jpg|png|webp|pdf)$/.test(key);
}

/**
 * Server-side access policy. The caller MUST supply an authenticated identity
 * after independently validating the user's role and ownership.
 */
export function canAccessEvidence({ viewerId, ownerId, role, explicitGrant = false } = {}) {
  if (typeof viewerId !== 'string' || !viewerId || typeof ownerId !== 'string' || !ownerId) return false;
  if (viewerId === ownerId) return true;
  if (role === 'ADMIN' || role === 'MODERATOR') return true;
  return explicitGrant === true;
}

/** Cheap magic-byte checks, not anti-virus scanning or exhaustive validation. */
export function matchesEvidenceSignature(bytes, mime) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength < 5) return false;
  if (!Object.hasOwn(ALLOWED_MIME, mime)) return false;
  const match = (seq, offset = 0) => bytes.byteLength >= offset + seq.length && seq.every((b, i) => bytes[offset + i] === b);
  switch (mime) {
    case 'image/jpeg': return match([0xff, 0xd8, 0xff]);
    case 'image/png': return match([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    case 'image/webp': return match([0x52, 0x49, 0x46, 0x46]) && match([0x57, 0x45, 0x42, 0x50], 8);
    case 'application/pdf': return match([0x25, 0x50, 0x44, 0x46, 0x2d]);
    default: return false;
  }
}

/**
 * Prevent accidental destructive E2E runs against externally hosted services.
 * This intentionally only accepts loopback HTTP endpoints.
 */
export function assertLocalTestTarget(url) {
  let parsed;
  try { parsed = new URL(url); } catch { throw new Error('Invalid test target URL'); }
  const loopback = ['localhost', '127.0.0.1', '[::1]'];
  if (parsed.protocol !== 'http:' || !loopback.includes(parsed.hostname) || parsed.username || parsed.password) {
    throw new Error('E2E target must be a local HTTP loopback endpoint');
  }
  return parsed.origin;
}
