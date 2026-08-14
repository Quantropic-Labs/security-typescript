import { SecurityConstants } from "../configurations/security-constants.js";
import { SupportedHashAlgorithms } from "../configurations/supported-hash-algorithms.js";
import type { HashAlgorithm } from "./hash-algorithm.js";

/**
 * Immutable PBKDF2/HKDF configuration. All parameters are validated at creation.
 *
 * @remarks
 * Do not construct manually. Use versioned presets such as {@link KdfOptions.V1}
 * or the {@link KdfOptions.create} factory for custom (non-standard) configurations.
 */
export class KdfOptions {
  /** PBKDF2 iteration count. Must be at least 100_000. */
  readonly pbkdf2Iterations: number;

  /** Hash algorithm used by PBKDF2 and HKDF. Supported: SHA-256, SHA-384, SHA-512. */
  readonly hashAlgorithm: HashAlgorithm;

  private constructor(pbkdf2Iterations: number, hashAlgorithm: HashAlgorithm) {
    if (pbkdf2Iterations < SecurityConstants.Pbkdf2IterationsMinimum) {
      throw new RangeError(
        `PBKDF2 iterations must be at least ${SecurityConstants.Pbkdf2IterationsMinimum}.`
      );
    }
    if (!SupportedHashAlgorithms.includes(hashAlgorithm)) {
      throw new RangeError(
        `Unsupported hash algorithm: ${hashAlgorithm}. Supported: ${SupportedHashAlgorithms.join(", ")}.`
      );
    }

    this.pbkdf2Iterations = pbkdf2Iterations;
    this.hashAlgorithm = hashAlgorithm;

    Object.freeze(this);
  }

  /** Validates iterations and hash algorithm. */
  validate(): void {
    if (this.pbkdf2Iterations < SecurityConstants.Pbkdf2IterationsMinimum)
      throw new Error(`Pbkdf2Iterations (${this.pbkdf2Iterations}) below minimum`);

    if (!SupportedHashAlgorithms.includes(this.hashAlgorithm))
      throw new Error(`Invalid hash algorithm: ${this.hashAlgorithm}`);
  }

  /**
   * V1 preset: SHA-256, 600_000 iterations.
   * These exact values are frozen for all V1-derived keys.
   */
  static readonly V1: KdfOptions = Object.freeze(
    new KdfOptions(600_000, "SHA-256")
  );
}