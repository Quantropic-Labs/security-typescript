import { CryptoService } from "../../src/crypto/crypto.service.js";
import { CryptoVersion } from "../../src/crypto/crypto-version.js";
import { SecurityConstants } from "../../src/configurations/security-constants.js";
import { SecurityUtils } from "../../src/utils/security.utils.js";
import { describe, it, expect, beforeAll } from "vitest";
import type { TestUser, UserMetadata, NestedDto } from "./test-dtos.js";

describe("CryptoService", () => {
  const crypto = new CryptoService();
  let validKey: Uint8Array;

  beforeAll(() => {
    validKey = crypto.generateRandomBytes(SecurityConstants.KeySizeBytes);
  });

  describe("Encrypt/Decrypt", () => {
    it("should encrypt and decrypt string round-trip", async () => {
      const original = "Hello, World! 🔐";
      const encrypted = await crypto.encryptData(original, validKey);
      const decrypted = await crypto.decryptData<string>(encrypted, validKey);
      expect(decrypted).toBe(original);
    });

    it("should encrypt and decrypt complex object round-trip", async () => {
      const metadata: UserMetadata = {
        created: new Date().toISOString(),
        verified: true,
      };
      const original: TestUser = {
        id: globalThis.crypto.randomUUID(),
        name: "Alice",
        email: "alice@example.com",
        roles: ["admin", "user"],
        metadata,
      };

      const encrypted = await crypto.encryptData(original, validKey);
      const decrypted = await crypto.decryptData<TestUser>(encrypted, validKey);

      expect(decrypted).not.toBeNull();
      expect(decrypted!.id).toBe(original.id);
      expect(decrypted!.name).toBe(original.name);
      expect(decrypted!.email).toBe(original.email);
      expect(decrypted!.roles).toEqual(original.roles);
      expect(decrypted!.metadata).toEqual(original.metadata);
    });

    it("should encrypt and decrypt Uint8Array round-trip", async () => {
      const original = new Uint8Array([1, 2, 3, 4, 5]);
      const encrypted = await crypto.encryptData(original, validKey);
      const decrypted = await crypto.decryptData<Uint8Array>(
        encrypted,
        validKey,
        true,
      );
      expect(decrypted).toEqual(original);
    });
  });

  describe("Key Validation", () => {
    it("should throw on key with invalid length", async () => {
      const invalidKey = new Uint8Array(64); // 512-bit, invalid for AES
      await expect(crypto.encryptData("test", invalidKey)).rejects.toThrow();
    });

    it("should throw on null key during encrypt", async () => {
      await expect(
        crypto.encryptData("test", null as unknown as Uint8Array),
      ).rejects.toThrow();
    });

    it("should throw on null key during decrypt", async () => {
      const encrypted = await crypto.encryptData("test", validKey);
      await expect(
        crypto.decryptData<string>(encrypted, null as unknown as Uint8Array),
      ).rejects.toThrow();
    });

    it("should throw on wrong key during decrypt", async () => {
      const original = "Secret message";
      const encrypted = await crypto.encryptData(original, validKey);
      const wrongKey = crypto.generateRandomBytes(
        SecurityConstants.KeySizeBytes,
      );
      await expect(
        crypto.decryptData<string>(encrypted, wrongKey),
      ).rejects.toThrow(/Decryption failed|authentication tag/);
    });
  });

  describe("Input Validation", () => {
    it("should return null for empty encrypted string", async () => {
      const result = await crypto.decryptData<string>("", validKey);
      expect(result).toBeNull();
    });

    it("should throw on invalid Base64", async () => {
      await expect(
        crypto.decryptData<string>("!@#InvalidBase64$$$", validKey),
      ).rejects.toThrow();
    });

    it("should throw on too short data", async () => {
      const tooShort = SecurityUtils.toBase64(new Uint8Array([1, 2, 3, 4, 5]));
      await expect(
        crypto.decryptData<string>(tooShort, validKey),
      ).rejects.toThrow(/Invalid format|too short/);
    });

    it("should throw on corrupted data", async () => {
      const original = "Important data";
      const encrypted = await crypto.encryptData(original, validKey);
      const encryptedBytes = SecurityUtils.fromBase64(encrypted);
      encryptedBytes[Math.floor(encryptedBytes.length / 2)] ^= 0xff;
      const corrupted = SecurityUtils.toBase64(encryptedBytes);
      await expect(
        crypto.decryptData<string>(corrupted, validKey),
      ).rejects.toThrow(/Decryption failed|authentication tag/);
    });

    it("should throw on tampered tag", async () => {
      const original = "Important data";
      const encrypted = await crypto.encryptData(original, validKey);
      const encryptedBytes = SecurityUtils.fromBase64(encrypted);
      encryptedBytes[encryptedBytes.length - 1] ^= 0xff;
      const tampered = SecurityUtils.toBase64(encryptedBytes);
      await expect(
        crypto.decryptData<string>(tampered, validKey),
      ).rejects.toThrow(/Decryption failed|authentication tag/);
    });
  });

  describe("Determinism & Randomness", () => {
    it("should produce different output for same input", async () => {
      const original = "Same message";
      const encrypted1 = await crypto.encryptData(original, validKey);
      const encrypted2 = await crypto.encryptData(original, validKey);
      expect(encrypted1).not.toBe(encrypted2);
      expect(await crypto.decryptData<string>(encrypted1, validKey)).toBe(
        original,
      );
      expect(await crypto.decryptData<string>(encrypted2, validKey)).toBe(
        original,
      );
    });

    it("should produce valid Base64 output", async () => {
      const original = "Test";
      const encrypted = await crypto.encryptData(original, validKey);
      const bytes = SecurityUtils.fromBase64(encrypted);
      expect(bytes.length).toBeGreaterThan(0);
    });
  });

  describe("Edge Cases & Unicode", () => {
    it("should handle Unicode content", async () => {
      const original = "Пароль 🔐 密码 🗝️ emoji 🎉";
      const encrypted = await crypto.encryptData(original, validKey);
      const decrypted = await crypto.decryptData<string>(encrypted, validKey);
      expect(decrypted).toBe(original);
    });

    it("should handle very long string", async () => {
      const original = "X".repeat(100_000);
      const encrypted = await crypto.encryptData(original, validKey);
      const decrypted = await crypto.decryptData<string>(encrypted, validKey);
      expect(decrypted).toBe(original);
    });

    it("should handle deeply nested object", async () => {
      const original: NestedDto = {
        level1: {
          level2: {
            value: "Deep value",
            items: [1, 2, 3],
          },
        },
      };
      const encrypted = await crypto.encryptData(original, validKey);
      const decrypted = await crypto.decryptData<NestedDto>(
        encrypted,
        validKey,
      );
      expect(decrypted?.level1?.level2?.value).toBe("Deep value");
      expect(decrypted?.level1?.level2?.items).toEqual([1, 2, 3]);
    });

    it("should handle nullable object with null properties", async () => {
      const original: TestUser = {
        id: globalThis.crypto.randomUUID(),
        name: null,
        email: null,
        roles: null,
        metadata: null,
      };
      const encrypted = await crypto.encryptData(original, validKey);
      const decrypted = await crypto.decryptData<TestUser>(encrypted, validKey);
      expect(decrypted).not.toBeNull();
      expect(decrypted!.id).toBe(original.id);
      expect(decrypted!.name).toBeNull();
    });
  });

  describe("GenerateRandomBytes", () => {
    it("should return 32 bytes by default", () => {
      const bytes = crypto.generateRandomBytes();
      expect(bytes.length).toBe(SecurityConstants.KeySizeBytes);
    });

    it("should return specified length", () => {
      const bytes = crypto.generateRandomBytes(64);
      expect(bytes.length).toBe(64);
    });

    it("should produce different values on multiple calls", () => {
      const bytes1 = crypto.generateRandomBytes(32);
      const bytes2 = crypto.generateRandomBytes(32);
      expect(bytes1).not.toEqual(bytes2);
    });

    it("should return empty array for zero length", () => {
      const bytes = crypto.generateRandomBytes(0);
      expect(bytes.length).toBe(0);
    });
  });

  describe("Format Version", () => {
    it("should support V1 format", async () => {
      const original = "Versioned format test";
      const encrypted = await crypto.encryptData(
        original,
        validKey,
        CryptoVersion.V1,
      );
      const decrypted = await crypto.decryptData<string>(encrypted, validKey);
      expect(decrypted).toBe(original);
    });
  });
});