import { SecurityUtils } from '../utils/security.utils.js';
import { AesGcmOptions } from './aes-gcm-options.js';
import { CryptoProfileRegistry } from './crypto-profile-registry.js';
import { CryptoProfile } from './crypto-profile.js';
import { CryptoVersion } from './crypto-version.js';

/**
 * AES-GCM encryption/decryption service with JSON serialization.
 * Encrypted output format (Base64): [Nonce][Ciphertext+Tag].
 */
export class CryptoService {

   /**
   * Encrypts a serializable object to a Base64 string.
   * @param dataModel - Object or Uint8Array to encrypt.
   * @param key - AES-256 key (32 bytes).
   * @returns Base64-encoded ciphertext with prepended nonce.
   */
  async encryptData<T>(dataModel: T, key: Uint8Array, version: CryptoVersion = CryptoVersion.V1): Promise<string> {
    const profile: CryptoProfile = CryptoProfileRegistry.getProfile(version);
    const opts: AesGcmOptions = profile.aesGcmOptions;
    opts.validate();

    const encoder = new TextEncoder();
    let jsonString: string;
    
    if (ArrayBuffer.isView(dataModel) && dataModel.constructor === Uint8Array) {
      jsonString = `"${SecurityUtils.toBase64(dataModel)}"`;
    } else {
      jsonString = JSON.stringify(dataModel);
    }

    const plainBytes = encoder.encode(jsonString);
    const nonce = crypto.getRandomValues(new Uint8Array(opts.nonceSize));

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key as BufferSource, 
      'AES-GCM',
      false,
      ['encrypt']
    );

    let associatedData: BufferSource = new Uint8Array(0);

    if (opts.associatedData != null){
      associatedData = opts.associatedData as BufferSource;
    }

    const encryptedContent = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
        tagLength: opts.tagSize * 8,
        additionalData: associatedData
      },
      cryptoKey,
      plainBytes
    );

    const result = new Uint8Array(1 + opts.nonceSize + encryptedContent.byteLength);
    result[0] = version;
    result.set(nonce, 1);
    result.set(new Uint8Array(encryptedContent), 1 + opts.nonceSize);
    return SecurityUtils.toBase64(result);
  }

   /**
   * Decrypts a Base64-encoded ciphertext back to the original object.
   * @param encryptedBase64 - The encrypted data.
   * @param key - AES-256 key (32 bytes).
   * @returns Deserialized object, or null if input is empty.
   * @throws If authentication tag mismatch or corrupted data.
   */
  async decryptData<T>(encryptedBase64: string, key: Uint8Array, isBytes: boolean = false): Promise<T | null> {
    if (!encryptedBase64)
      return null;

    const encryptedBytes: Uint8Array<ArrayBufferLike> = SecurityUtils.fromBase64(encryptedBase64);

    const version: CryptoVersion = encryptedBytes[0] as CryptoVersion;
    const payload: Uint8Array<ArrayBuffer> = encryptedBytes.slice(1);

    const profile: CryptoProfile = CryptoProfileRegistry.getProfile(version);
    const opts: AesGcmOptions = profile.aesGcmOptions;
    opts.validate();

    if (payload.length < opts.nonceSize + opts.tagSize)
      throw new Error(`Invalid format: minimum expected ${opts.nonceSize + opts.tagSize} byte.`);

    const nonce = payload.slice(0, opts.nonceSize);
    const ciphertextWithTag = payload.slice(opts.nonceSize);

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key as BufferSource,
      'AES-GCM',
      false,
      ['decrypt']
    );

    try {

      let associatedData: BufferSource = new Uint8Array(0);

      if (opts.associatedData != null)
        associatedData = opts.associatedData as BufferSource;

      const decryptedBuffer = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: nonce,
          tagLength: opts.tagSize * 8,
          additionalData: associatedData
        },
        cryptoKey,
        ciphertextWithTag
      );

      const decoder = new TextDecoder();
      const jsonString = decoder.decode(decryptedBuffer);
      const parsed = JSON.parse(jsonString);

      if (isBytes && typeof parsed === 'string') {
        return SecurityUtils.fromBase64(parsed) as unknown as T;
      }

      return parsed as T;
    } catch (e) {
      console.error('Decryption error:', e);
      throw new Error("Decryption failed: authentication tag mismatch or corrupted data.");
    }
  }

   /**
   * Generates cryptographically secure random bytes.
   * @param length - Number of bytes (default 32).
   * @returns Uint8Array of random bytes.
   */
  generateRandomBytes = (length = 32): Uint8Array => crypto.getRandomValues(new Uint8Array(length));
}