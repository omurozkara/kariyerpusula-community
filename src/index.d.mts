export declare const ALLOWED_MIME: Readonly<Record<'image/jpeg' | 'image/png' | 'image/webp' | 'application/pdf', string>>;
export type EvidenceMime = keyof typeof ALLOWED_MIME;
export declare function createEvidenceKey(resourceId: string, mime: EvidenceMime): string;
export declare function validateEvidenceKey(key: unknown): boolean;
export declare function canAccessEvidence(input?: {
  viewerId?: string | null;
  ownerId?: string | null;
  role?: string | null;
  explicitGrant?: boolean;
}): boolean;
export declare function matchesEvidenceSignature(bytes: Uint8Array, mime: string): boolean;
export declare function assertLocalTestTarget(url: string): string;
