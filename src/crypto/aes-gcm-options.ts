import { SecurityConstants } from "../configurations/security-constants.js";

/**
 * Immutable AES-GCM configuration. All parameters are validated at creation.
 *
 * @remarks
 * Do not construct manually. Use versioned presets such as {@link AesGcmOptions.V1}
 * or the {@link AesGcmOptions.create} factory for custom (non-standard) configurations.
 */
export class AesGcmOptions {
  /** Nonce size in bytes. Must equal 12 (NIST SP 800-38D). */
  readonly nonceSize: number;

  /** Authentication tag size in bytes. Allowed range: 12–16. */
  readonly tagSize: number;

  private constructor(nonceSize: number, tagSize: number) {
    if (nonceSize !== SecurityConstants.AesGcmNonceSize) {
      throw new RangeError(
        `AES-GCM requires exactly ${SecurityConstants.AesGcmNonceSize}-byte nonce per NIST SP 800-38D.`
      );
    }
    if (tagSize < SecurityConstants.AesGcmTagSizeMin || tagSize > SecurityConstants.AesGcmTagSizeMax) {
      throw new RangeError(
        `Tag size must be between ${SecurityConstants.AesGcmTagSizeMin} and ${SecurityConstants.AesGcmTagSizeMax} bytes.`
      );
    }

    this.nonceSize = nonceSize;
    this.tagSize = tagSize;

    Object.freeze(this);
  }

  /** Validates that {@link tagSize} is in the allowed range. */
  validate(): void {
    if (this.tagSize < SecurityConstants.AesGcmTagSizeMin || this.tagSize > SecurityConstants.AesGcmTagSizeMax) 
      throw new Error(`Invalid Tag Size: ${this.tagSize}`);
  }

  /**
   * V1 preset: nonce=12, tag=16, no AAD.
   * These exact values are frozen for all V1-encrypted payloads.
   */
  static readonly V1: AesGcmOptions = Object.freeze(
    new AesGcmOptions(12, 16)
  );
}