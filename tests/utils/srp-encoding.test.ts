import { describe, it, expect, beforeAll } from 'vitest';
import { SrpEncoding } from '../../src/utils/srp-encoding.js';
import { SrpContextFactory } from '../../src/srp/srp-context-factory.js';
import { SrpGroup } from '../../src/srp/srp-group.js';
import { SecurityUtils } from '../../src/utils/security.utils.js';

describe('SrpEncoding', () => {
    const group = SrpGroup.Rfc5054_3072;
    let ctx: Awaited<ReturnType<typeof SrpContextFactory.create>>;

    beforeAll(async () => {
        ctx = await SrpContextFactory.create(group);
    });

    describe('toModulusBytes', () => {
        it('should pad small value to modulus size', () => {
            const result = SrpEncoding.toModulusBytes(ctx, 1n);
            expect(result.length).toBe(ctx.modulusSize);
        });

        it('should handle zero', () => {
            const result = SrpEncoding.toModulusBytes(ctx, 0n);
            expect(result.length).toBe(ctx.modulusSize);
            expect([...result].every(b => b === 0)).toBe(true);
        });

        it('should handle large value (N - 1)', () => {
            const result = SrpEncoding.toModulusBytes(ctx, ctx.N - 1n);
            expect(result.length).toBe(ctx.modulusSize);
        });
    });

    describe('toHashBytes', () => {
        it('should pad small value to hash size', () => {
            const result = SrpEncoding.toHashBytes(ctx, 1n);
            expect(result.length).toBe(ctx.hashSize);
        });

        it('should handle zero', () => {
            const result = SrpEncoding.toHashBytes(ctx, 0n);
            expect(result.length).toBe(ctx.hashSize);
        });
    });

    describe('computeSessionKey', () => {
        it('should return hash-sized bytes', async () => {
            const S = 12345n;
            const key = await SrpEncoding.computeSessionKey(ctx, S);
            expect(key).toBeInstanceOf(Uint8Array);
            expect(key.length).toBe(ctx.hashSize);
        });

        it('should be deterministic for same S', async () => {
            const S = 99999n;
            const k1 = await SrpEncoding.computeSessionKey(ctx, S);
            const k2 = await SrpEncoding.computeSessionKey(ctx, S);
            expect(k1).toEqual(k2);
        });

        it('should produce different keys for different S', async () => {
            const k1 = await SrpEncoding.computeSessionKey(ctx, 111n);
            const k2 = await SrpEncoding.computeSessionKey(ctx, 222n);
            expect(k1).not.toEqual(k2);
        });
    });

    describe('hashModuli', () => {
        it('should return non-zero bigint for valid A and B', async () => {
            const A = await SecurityUtils.expModAsync(ctx.g, 5n, ctx.N);
            const B = await SecurityUtils.expModAsync(ctx.g, 7n, ctx.N);
            const u = await SrpEncoding.hashModuli(ctx, A, B);
            expect(typeof u).toBe('bigint');
            expect(u).toBeGreaterThan(0n);
        });

        it('should be deterministic', async () => {
            const u1 = await SrpEncoding.hashModuli(ctx, 123n, 456n);
            const u2 = await SrpEncoding.hashModuli(ctx, 123n, 456n);
            expect(u1).toBe(u2);
        });

        it('should produce different u for different inputs', async () => {
            const u1 = await SrpEncoding.hashModuli(ctx, 10n, 20n);
            const u2 = await SrpEncoding.hashModuli(ctx, 10n, 21n);
            expect(u1).not.toBe(u2);
        });
    });

    describe('computeM1', () => {
        it('should return hash-sized bytes', async () => {
            const A = 10n, B = 20n;
            const K = new Uint8Array(ctx.hashSize).fill(0xAA);
            const salt = new Uint8Array(16).fill(0xBB);
            const m1 = await SrpEncoding.computeM1(ctx, A, B, K, 'alice', salt);
            expect(m1).toBeInstanceOf(Uint8Array);
            expect(m1.length).toBe(ctx.hashSize);
        });

        it('should be deterministic', async () => {
            const A = 100n, B = 200n;
            const K = new Uint8Array(ctx.hashSize).fill(0xCC);
            const salt = new Uint8Array(16).fill(0xDD);
            const m1a = await SrpEncoding.computeM1(ctx, A, B, K, 'bob', salt);
            const m1b = await SrpEncoding.computeM1(ctx, A, B, K, 'bob', salt);
            expect(m1a).toEqual(m1b);
        });

        it('should differ for different identities', async () => {
            const A = 100n, B = 200n;
            const K = new Uint8Array(ctx.hashSize).fill(0xCC);
            const salt = new Uint8Array(16).fill(0xDD);
            const m1a = await SrpEncoding.computeM1(ctx, A, B, K, 'alice', salt);
            const m1b = await SrpEncoding.computeM1(ctx, A, B, K, 'bob', salt);
            expect(m1a).not.toEqual(m1b);
        });

        it('should differ for different session keys', async () => {
            const A = 100n, B = 200n;
            const K1 = new Uint8Array(ctx.hashSize).fill(0x11);
            const K2 = new Uint8Array(ctx.hashSize).fill(0x22);
            const salt = new Uint8Array(16).fill(0xDD);
            const m1a = await SrpEncoding.computeM1(ctx, A, B, K1, 'alice', salt);
            const m1b = await SrpEncoding.computeM1(ctx, A, B, K2, 'alice', salt);
            expect(m1a).not.toEqual(m1b);
        });
    });

    describe('computeM2', () => {
        it('should return hash-sized bytes', async () => {
            const A = 10n;
            const m1 = new Uint8Array(ctx.hashSize).fill(0x11);
            const K = new Uint8Array(ctx.hashSize).fill(0x22);
            const m2 = await SrpEncoding.computeM2(ctx, A, m1, K);
            expect(m2).toBeInstanceOf(Uint8Array);
            expect(m2.length).toBe(ctx.hashSize);
        });

        it('should be deterministic', async () => {
            const A = 100n;
            const m1 = new Uint8Array(ctx.hashSize).fill(0x33);
            const K = new Uint8Array(ctx.hashSize).fill(0x44);
            const m2a = await SrpEncoding.computeM2(ctx, A, m1, K);
            const m2b = await SrpEncoding.computeM2(ctx, A, m1, K);
            expect(m2a).toEqual(m2b);
        });

        it('should differ for different M1', async () => {
            const A = 100n;
            const m1a = new Uint8Array(ctx.hashSize).fill(0x11);
            const m1b = new Uint8Array(ctx.hashSize).fill(0x22);
            const K = new Uint8Array(ctx.hashSize).fill(0x33);
            const m2a = await SrpEncoding.computeM2(ctx, A, m1a, K);
            const m2b = await SrpEncoding.computeM2(ctx, A, m1b, K);
            expect(m2a).not.toEqual(m2b);
        });
    });
});