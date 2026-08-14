import { describe, it, expect } from 'vitest';
import { SrpClientService } from '../../src/srp/srp-client-service.js';
import { SrpContextFactory } from '../../src/srp/srp-context-factory.js';
import { SrpGroup } from '../../src/srp/srp-group.js';
import { SecurityUtils } from '../../src/utils/security.utils.js';
import { SrpEncoding } from '../../src/utils/srp-encoding.js';

describe('SrpClientService', () => {
    const srpClient = new SrpClientService();
    const validGroup = SrpGroup.Rfc5054_3072;

    async function getContext(group: SrpGroup) {
        return await SrpContextFactory.create(group);
    }

    function toBase64(value: bigint, length: number): string {
        return SecurityUtils.toBase64(SecurityUtils.bigIntToFixedBytes(value, length));
    }

    describe('generateSrpProof', () => {
        it('should throw on null salt', async () => {
            await expect(srpClient.generateSrpProof('user', new Uint8Array(32), null as unknown as string, 'AA==', validGroup))
                .rejects.toThrow();
        });

        it('should throw on null B', async () => {
            await expect(srpClient.generateSrpProof('user', new Uint8Array(32), 'AA==', null as unknown as string, validGroup))
                .rejects.toThrow();
        });

        it('should throw on invalid salt Base64', async () => {
            await expect(srpClient.generateSrpProof('user', new Uint8Array(32), 'not-base64!!!', 'AA==', validGroup))
                .rejects.toThrow();
        });

        it('should throw on invalid B Base64', async () => {
            await expect(srpClient.generateSrpProof('user', new Uint8Array(32), 'AA==', 'not-base64!!!', validGroup))
                .rejects.toThrow();
        });

        it('should throw when B is zero', async () => {
            await expect(srpClient.generateSrpProof('user', new Uint8Array(32), 'AA==', 'AA==', validGroup))
                .rejects.toThrow(/Invalid|B % N|Critical error/);
        });

        it('should throw when B equals modulus', async () => {
            const ctx = await getContext(validGroup);
            const b = toBase64(ctx.N, ctx.modulusSize);
            await expect(srpClient.generateSrpProof('user', new Uint8Array(32), 'AA==', b, validGroup))
                .rejects.toThrow(/Critical error.*B % N|Invalid|out of range/);
        });

        it('should return proof for valid inputs', async () => {
            const ctx = await getContext(validGroup);
            const authHash = new Uint8Array(32).fill(0xAB);
            const salt = new Uint8Array(16).fill(0xCD);
            const saltB64 = SecurityUtils.toBase64(salt);

            const bBytes = crypto.getRandomValues(new Uint8Array(32));
            const b = SecurityUtils.bytesToBigInt(bBytes);
            const B = await SecurityUtils.expModAsync(ctx.g, b, ctx.N);
            const bB64 = toBase64(B, ctx.modulusSize);

            const result = await srpClient.generateSrpProof('alice', authHash, saltB64, bB64, validGroup);

            expect(result.A).toBeTruthy();
            expect(result.M1).toBeTruthy();
            expect(result.SessionKeyK).toBeInstanceOf(Uint8Array);
            expect(result.SessionKeyK.length).toBe(ctx.hashSize);
        });
    });

    describe('generateSrpVerifier', () => {
        it('should throw on null authHash', async () => {
            await expect(srpClient.generateSrpVerifier(null as unknown as string, validGroup))
                .rejects.toThrow();
        });

        it('should throw on invalid Base64', async () => {
            await expect(srpClient.generateSrpVerifier('!!!', validGroup))
                .rejects.toThrow();
        });

        it('should return deterministic Base64 for valid hash', async () => {
            const hash = new Uint8Array(32).fill(0xAB);
            const hashB64 = SecurityUtils.toBase64(hash);
            const v1 = await srpClient.generateSrpVerifier(hashB64, validGroup);
            const v2 = await srpClient.generateSrpVerifier(hashB64, validGroup);
            expect(v1).toBe(v2);
            expect(v1).toBeTruthy();
        });
    });

    describe('verifyServerM2', () => {
        it('should return true for correct M2', async () => {
            const ctx = await getContext(validGroup);
            const sessionKey = crypto.getRandomValues(new Uint8Array(ctx.hashSize));
            const A = await SecurityUtils.expModAsync(ctx.g, 123n, ctx.N);
            const aB64 = toBase64(A, ctx.modulusSize);
            const m1 = crypto.getRandomValues(new Uint8Array(ctx.hashSize));
            const m1B64 = SecurityUtils.toBase64(m1);
            const validM2 = SecurityUtils.toBase64(await SrpEncoding.computeM2(ctx, A, m1, sessionKey));

            const result = await srpClient.verifyServerM2(aB64, m1B64, sessionKey, validM2, validGroup);
            expect(result).toBe(true);
        });

        it('should return false for wrong M2', async () => {
            const ctx = await getContext(validGroup);
            const sessionKey = crypto.getRandomValues(new Uint8Array(ctx.hashSize));
            const A = await SecurityUtils.expModAsync(ctx.g, 123n, ctx.N);
            const aB64 = toBase64(A, ctx.modulusSize);
            const m1 = crypto.getRandomValues(new Uint8Array(ctx.hashSize));
            const m1B64 = SecurityUtils.toBase64(m1);
            const wrongM2 = SecurityUtils.toBase64(crypto.getRandomValues(new Uint8Array(ctx.hashSize)));

            const result = await srpClient.verifyServerM2(aB64, m1B64, sessionKey, wrongM2, validGroup);
            expect(result).toBe(false);
        });

        it('should throw on null public A', async () => {
            await expect(srpClient.verifyServerM2(null as unknown as string, 'AA==', new Uint8Array(1), 'AA==', validGroup))
                .rejects.toThrow();
        });
    });
});