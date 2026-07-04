import { HashAlgorithm } from "../crypto/hash-algorithm.js";

export const SecurityConstants = {
  AesGcmNonceSize: 12,
  AesGcmTagSize: 16,
  AesGcmTagSizeMin: 12,
  AesGcmTagSizeMax: 16,
  KeySizeBytes: 32, // 256 bits
  Pbkdf2IterationsDefault: 600_000,
  Pbkdf2IterationsMinimum: 100_000
} as const;

export const HashSizes: Record<HashAlgorithm, number> = {
  'SHA-256': 32,
  'SHA-384': 48,
  'SHA-512': 64,
};