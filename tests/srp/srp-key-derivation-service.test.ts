import { describe, it, expect } from 'vitest';
import { SrpKeyDerivationService } from '../../src/srp/srp-key-derivation.service.js';
import { SrpGroup } from '../../src/srp/srp-group.js';
import { CryptoVersion } from '../../src/crypto/crypto-version.js';

describe('SrpKeyDerivationService', () => {
    const sut = new SrpKeyDerivationService();
    const validSalt = new Uint8Array(16).fill(0xCD);
    const validGroup = SrpGroup.Rfc5054_3072;
    const validVersion = CryptoVersion.V1;

    describe('deriveAuthHashForSrp', () => {
        it('should return non-empty hash for valid inputs', async () => {
            const result = await sut.deriveAuthHashForSrp('user', 'password', validSalt, validGroup, validVersion);
            expect(result).toBeInstanceOf(Uint8Array);
            expect(result.length).toBeGreaterThan(0);
        });

        it.each([
            ['null', null as unknown as string],
            ['empty', ''],
            ['whitespace', '   '],
        ])('should throw on invalid identity (%s)', async (_, identity) => {
            await expect(sut.deriveAuthHashForSrp(identity, 'password', validSalt, validGroup, validVersion))
                .rejects.toThrow(/Identity cannot be null or empty/);
        });

        it.each([
            ['null', null as unknown as string],
            ['empty', ''],
            ['whitespace', '   '],
        ])('should throw on invalid password (%s)', async (_, password) => {
            await expect(sut.deriveAuthHashForSrp('user', password, validSalt, validGroup, validVersion))
                .rejects.toThrow(/Password cannot be null or empty/);
        });

        it('should throw on null salt', async () => {
            await expect(sut.deriveAuthHashForSrp('user', 'password', null as unknown as Uint8Array, validGroup, validVersion))
                .rejects.toThrow(/Salt must be at least 16 bytes/);
        });

        it.each([
            ['0 bytes', new Uint8Array(0)],
            ['1 byte', new Uint8Array(1)],
            ['15 bytes', new Uint8Array(15)],
        ])('should throw on short salt (%s)', async (_, shortSalt) => {
            await expect(sut.deriveAuthHashForSrp('user', 'password', shortSalt, validGroup, validVersion))
                .rejects.toThrow(/Salt must be at least 16 bytes/);
        });

        it('should produce same output for same inputs', async () => {
            const salt = new TextEncoder().encode('fixed-salt-12345');
            const hash1 = await sut.deriveAuthHashForSrp('alice', 'secret', salt, validGroup, validVersion);
            const hash2 = await sut.deriveAuthHashForSrp('alice', 'secret', salt, validGroup, validVersion);
            expect(hash1).toEqual(hash2);
        });

        it('should produce different output for different identities', async () => {
            const salt = new TextEncoder().encode('fixed-salt-12345');
            const hash1 = await sut.deriveAuthHashForSrp('alice', 'secret', salt, validGroup, validVersion);
            const hash2 = await sut.deriveAuthHashForSrp('bob', 'secret', salt, validGroup, validVersion);
            expect(hash1).not.toEqual(hash2);
        });
    });
});