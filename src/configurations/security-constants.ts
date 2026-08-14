import type { HashAlgorithm } from "../crypto/hash-algorithm.js";

/**
 * Algorithmic constraints that are physically immutable.
 * These do not change between crypto versions.
 */
export const SecurityConstants = {
  /** Standard nonce size for AES-GCM (96 bits). Fixed by NIST SP 800-38D. */
  AesGcmNonceSize: 12,

  /** Minimum allowed authentication tag size (96 bits). */
  AesGcmTagSizeMin: 12,

  /** Maximum allowed authentication tag size (128 bits). */
  AesGcmTagSizeMax: 16,

  /** Key size for AES-256 (256 bits). */
  KeySizeBytes: 32,

  /** Absolute minimum PBKDF2 iterations for any profile version. */
  Pbkdf2IterationsMinimum: 100_000,
} as const;

export const HashSizes: Record<HashAlgorithm, number> = {
  'SHA-256': 32,
  'SHA-384': 48,
  'SHA-512': 64,
} as const;