import { describe, it, expect } from 'vitest';
import { KeyDerivationService } from '../../src/crypto/key-derivation.service.js';
import { CryptoVersion } from '../../src/crypto/crypto-version.js';
import { SecurityConstants } from '../../src/configurations/security-constants.js';
import { SecurityUtils } from '../../src/utils/security.utils.js';

describe('KeyDerivationService', () => {
  const service = new KeyDerivationService();
  const testLogin = 'TestLogin';
  const testPassword = 'MyStr0ng!P@ssw0rd';
  const cryptoVersion = CryptoVersion.V1;

  function generateSalt(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(32));
  }

  describe('Basic Functionality', () => {
    it('should derive valid keys with default options', async () => {
      const salt = generateSalt();
      const { kek, authHash } = await service.deriveKeysFromPassword(testLogin, testPassword, salt, cryptoVersion);
      expect(kek).toBeInstanceOf(Uint8Array);
      expect(kek.length).toBe(SecurityConstants.KeySizeBytes);
      expect(authHash).toBeTruthy();
      expect(SecurityUtils.fromBase64(authHash).length).toBe(SecurityConstants.KeySizeBytes);
    });

    it('should produce same output for same inputs', async () => {
      const password = 'consistent_password';
      const salt = new TextEncoder().encode('fixed_salt_32_bytes!!');
      const result1 = await service.deriveKeysFromPassword(testLogin, password, salt, cryptoVersion);
      const result2 = await service.deriveKeysFromPassword(testLogin, password, salt, cryptoVersion);
      expect(result1.kek).toEqual(result2.kek);
      expect(result1.authHash).toBe(result2.authHash);
    });

    it('should produce different keys for different passwords', async () => {
      const salt = generateSalt();
      const result1 = await service.deriveKeysFromPassword(testLogin, 'password1', salt, cryptoVersion);
      const result2 = await service.deriveKeysFromPassword(testLogin, 'password2', salt, cryptoVersion);
      expect(result1.kek).not.toEqual(result2.kek);
      expect(result1.authHash).not.toBe(result2.authHash);
    });

    it('should produce different keys for different salts', async () => {
      const salt1 = generateSalt();
      const salt2 = generateSalt();
      const result1 = await service.deriveKeysFromPassword(testLogin, testPassword, salt1, cryptoVersion);
      const result2 = await service.deriveKeysFromPassword(testLogin, testPassword, salt2, cryptoVersion);
      expect(result1.kek).not.toEqual(result2.kek);
      expect(result1.authHash).not.toBe(result2.authHash);
    });
  });

  describe('Input Validation', () => {
    it.each([
      ['null', null],
      ['empty', ''],
      ['whitespace', '   '],
    ])('should throw on invalid password (%s)', async (_, invalidPassword) => {
      const salt = generateSalt();
      await expect(
        service.deriveKeysFromPassword(testLogin, invalidPassword as string, salt, cryptoVersion)
      ).rejects.toThrow(/Password cannot be null or empty/);
    });

    it('should throw on null salt', async () => {
      await expect(
        service.deriveKeysFromPassword(testLogin, testPassword, null as unknown as Uint8Array, cryptoVersion)
      ).rejects.toThrow(/Salt must be not null|Salt must be at least/);
    });
  });

  describe('Security & Output Sanity', () => {
    it('should return valid non-zero kek and authHash', async () => {
      const salt = generateSalt();
      const { kek, authHash } = await service.deriveKeysFromPassword(testLogin, testPassword, salt, cryptoVersion);
      const decoded = SecurityUtils.fromBase64(authHash);
      expect(decoded.length).toBe(SecurityConstants.KeySizeBytes);
      expect([...decoded].some(b => b !== 0)).toBe(true);
      expect([...kek].some(b => b !== 0)).toBe(true);
    });
  });

  describe('Edge Cases', () => {
    it('should handle Unicode password', async () => {
      const unicodePassword = 'Пароль🔐密码🔑';
      const salt = generateSalt();
      const { kek, authHash } = await service.deriveKeysFromPassword(testLogin, unicodePassword, salt, cryptoVersion);
      expect(kek).toBeInstanceOf(Uint8Array);
      expect(kek.length).toBe(SecurityConstants.KeySizeBytes);
      expect(authHash).toBeTruthy();
    });

    it('should throw on empty salt array', async () => {
      await expect(
        service.deriveKeysFromPassword(testLogin, testPassword, new Uint8Array(0), cryptoVersion)
      ).rejects.toThrow(/at least 16 bytes/);
    });

    it('should handle very long password', async () => {
      const longPassword = 'A'.repeat(10_000);
      const salt = generateSalt();
      const { kek, authHash } = await service.deriveKeysFromPassword(testLogin, longPassword, salt, cryptoVersion);
      expect(kek).toBeInstanceOf(Uint8Array);
      expect(kek.length).toBe(SecurityConstants.KeySizeBytes);
      expect(authHash).toBeTruthy();
    });
  });
});