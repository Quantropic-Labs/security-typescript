import { HashSizes } from "../configurations/security-constants.js";
import { CryptoProfileRegistry } from "../crypto/crypto-profile-registry.js";
import { CryptoProfile } from "../crypto/crypto-profile.js";
import { CryptoVersion } from "../crypto/crypto-version.js";
import { KdfOptions } from "../crypto/kdf-options.js";
import { SrpContextFactory } from "../srp/srp-context-factory.js";
import { SrpGroup } from "../srp/srp-group.js";

/**
 * Two-stage key derivation: PBKDF2 (master key) → HKDF (sub-keys).
 */
export class SrpKeyDerivationService {

   /**
   * Derives an SRP-compatible authentication hash (output size = hash output length).
   * Identity is hashed as-is — caller must normalize (trim, lowercase, etc.) before calling.
   * @param identity - User identity (pre-normalized by caller).
   * @param identity - User identity.
   * @param password - User password.
   * @param salt - Random salt.
   * @param srpHashAlgorithm - SRP hash algorithm (SHA-256/384/512).
   * @param options - KDF configuration; uses default if omitted.
   * @returns Raw hash bytes for use as SRP verifier input (x).
   */
  async deriveAuthHashForSrp(identity: string, password: string, salt: Uint8Array, srpGroup: SrpGroup, version: CryptoVersion): Promise<Uint8Array> {
    if (!identity || identity.trim().length === 0)
      throw new Error('Identity cannot be null or empty.');
    
    if (!password || password.trim().length === 0)
      throw new Error('Password cannot be null or empty.');
        
    if (!salt || salt.length < 16)
      throw new Error('Salt must be at least 16 bytes.');

    const profile: CryptoProfile = CryptoProfileRegistry.getProfile(version);
    const opts: KdfOptions = profile.kdfOptions;
    opts.validate();

    const ctx = await SrpContextFactory.create(srpGroup);
    const srpHashAlgorithm = ctx.hashAlgorithmName;
    const srpHashSize = HashSizes[srpHashAlgorithm];;
    const combinedPassword = `${identity}:${password}`;
    const passwordBytes = new TextEncoder().encode(combinedPassword);

    const baseKey = await crypto.subtle.importKey(
      'raw', 
      passwordBytes as BufferSource, 
      'PBKDF2', 
      false, 
      ['deriveBits']
    );

    const masterKeyBits = await crypto.subtle.deriveBits({
      name: 'PBKDF2',
      salt: salt as BufferSource,
      iterations: opts.pbkdf2Iterations,
      hash: srpHashAlgorithm
    }, baseKey, srpHashSize * 8);

    const masterKey = await crypto.subtle.importKey(
      'raw', 
      masterKeyBits, 
      'HKDF', 
      false, 
      ['deriveBits']
    );

    const info = new TextEncoder().encode('SRP-AUTH-HASH-v1');
    const authBytes = await crypto.subtle.deriveBits(
      { 
        name: 'HKDF', 
        hash: srpHashAlgorithm, 
        salt: new Uint8Array(0), 
        info: info as BufferSource 
      },
      masterKey,
      srpHashSize * 8
    );

    return new Uint8Array(authBytes);
  }
}