import { HashSizes, SecurityConstants } from "../configurations/security-constants.js";
import { SecurityUtils } from "../utils/security.utils.js";
import { CryptoProfileRegistry } from "./crypto-profile-registry.js";
import { CryptoProfile } from "./crypto-profile.js";
import { CryptoVersion } from "./crypto-version.js";
import { KdfOptions } from "./kdf-options.js";

/**
 * Two-stage key derivation: PBKDF2 (master key) → HKDF (sub-keys).
 */
export class KeyDerivationService {

   /**
   * Derives KEK and Base64 AuthHash. Identity is hashed as-is — caller must 
   * normalize (trim, lowercase, etc.) before calling.
   * @param identity - User identity (pre-normalized by caller).
   * @param identity - User identity (email, username).
   * @param password - User password.
   * @param salt - Random salt.
   * @param options - KDF configuration; uses default if omitted.
   * @returns Object with `kek` (Uint8Array) and `authHash` (Base64 string).
   */
  async deriveKeysFromPassword(identity: string, password: string, salt: Uint8Array, version: CryptoVersion): Promise<{ kek: Uint8Array; authHash: string }> {
    if (!identity || identity.length === 0)
      throw new Error('Identity cannot be null or empty.');

    if (!password || password.trim().length === 0)
      throw new Error('Password cannot be null or empty.');

    if (!salt || salt.length < 16)
      throw new Error('Salt must be at least 16 bytes.');

    const profile: CryptoProfile = CryptoProfileRegistry.getProfile(version);
    const opts: KdfOptions = profile.kdfOptions;
    opts.validate();

    const safeSalt = new Uint8Array(salt);
    const encoder = new TextEncoder();

    const combinedPassword = `${identity}:${password}`;
    const passwordBytes = encoder.encode(combinedPassword);
    const baseKey = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits', 'deriveKey']);

    const hashSize = HashSizes[opts.hashAlgorithm] ?? 32;
    const masterKeyBits = await crypto.subtle.deriveBits({
      name: 'PBKDF2',
      salt: safeSalt,
      iterations: opts.pbkdf2Iterations,
      hash: opts.hashAlgorithm
    }, baseKey, hashSize * 8);

    const masterKey = await crypto.subtle.importKey('raw', masterKeyBits, 'HKDF', false, ['deriveBits']);

    const kek = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: opts.hashAlgorithm, salt: new Uint8Array(0), info: encoder.encode('AES-GCM-KEK-v1') },
      masterKey,
      SecurityConstants.KeySizeBytes * 8
    );

    const authBytes = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: opts.hashAlgorithm, salt: new Uint8Array(0), info: encoder.encode('SERVER-AUTH-HASH-v1') },
      masterKey,
      SecurityConstants.KeySizeBytes * 8
    );

    return {
      kek: new Uint8Array(kek),
      authHash: SecurityUtils.toBase64(new Uint8Array(authBytes)),
    };
  }
}