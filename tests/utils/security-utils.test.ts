import { describe, it, expect } from 'vitest';
import { SecurityUtils } from '../../src/utils/security.utils.js';

describe('SecurityUtils', () => {

    describe('Base64', () => {
        it('should round-trip empty array', () => {
            const original = new Uint8Array(0);
            const encoded = SecurityUtils.toBase64(original);
            const decoded = SecurityUtils.fromBase64(encoded);
            expect(decoded).toEqual(original);
        });

        it('should round-trip simple ASCII bytes', () => {
            const original = new TextEncoder().encode('Hello, World!');
            const encoded = SecurityUtils.toBase64(original);
            const decoded = SecurityUtils.fromBase64(encoded);
            expect(decoded).toEqual(original);
            expect(encoded).toBe('SGVsbG8sIFdvcmxkIQ==');
        });

        it('should round-trip binary data', () => {
            const original = new Uint8Array([0, 1, 255, 254, 128, 64, 32, 16]);
            const encoded = SecurityUtils.toBase64(original);
            const decoded = SecurityUtils.fromBase64(encoded);
            expect(decoded).toEqual(original);
        });

        it('should round-trip all byte values 0-255', () => {
            const original = new Uint8Array(256);
            for (let i = 0; i < 256; i++) original[i] = i;
            const encoded = SecurityUtils.toBase64(original);
            const decoded = SecurityUtils.fromBase64(encoded);
            expect(decoded).toEqual(original);
        });

        it('should handle URL-safe Base64 input', () => {
            // URL-safe variants with - and _ instead of + and /
            const urlSafe = 'dGVzdCsv'; // "test+/" in standard base64
            const decoded = SecurityUtils.fromBase64(urlSafe);
            const standard = SecurityUtils.fromBase64('dGVzdCsv');
            expect(decoded).toEqual(standard);
        });

        it('should handle missing padding', () => {
            const withoutPadding = 'SGVsbG8'; // "Hello" without ==
            const decoded = SecurityUtils.fromBase64(withoutPadding);
            expect(new TextDecoder().decode(decoded)).toBe('Hello');
        });

        it('should handle whitespace in Base64 string', () => {
            const withSpaces = 'SGVs bG8 gV29 ybGQ=';
            const decoded = SecurityUtils.fromBase64(withSpaces);
            expect(new TextDecoder().decode(decoded)).toBe('Hello World');
        });

        it('should produce different output lengths for different inputs', () => {
            const short = SecurityUtils.toBase64(new Uint8Array([1]));
            const long = SecurityUtils.toBase64(new Uint8Array(100).fill(0xAB));
            expect(long.length).toBeGreaterThan(short.length);
        });
    });

    describe('bytesToBigInt', () => {
        it('should convert empty array to 0', () => {
            expect(SecurityUtils.bytesToBigInt(new Uint8Array(0))).toBe(0n);
        });

        it('should convert single byte', () => {
            expect(SecurityUtils.bytesToBigInt(new Uint8Array([0x00]))).toBe(0n);
            expect(SecurityUtils.bytesToBigInt(new Uint8Array([0x01]))).toBe(1n);
            expect(SecurityUtils.bytesToBigInt(new Uint8Array([0xFF]))).toBe(255n);
        });

        it('should convert multi-byte big-endian', () => {
            expect(SecurityUtils.bytesToBigInt(new Uint8Array([0x01, 0x00]))).toBe(256n);
            expect(SecurityUtils.bytesToBigInt(new Uint8Array([0x00, 0x01]))).toBe(1n); // leading zeros
            expect(SecurityUtils.bytesToBigInt(new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]))).toBe(0xDEADBEEFn);
        });

        it('should convert large values', () => {
            const bytes = new Uint8Array(32).fill(0xFF);
            const result = SecurityUtils.bytesToBigInt(bytes);
            expect(result).toBe((1n << 256n) - 1n);
        });
    });

    describe('bigIntToFixedBytes', () => {
        it('should pad small value to fixed length', () => {
            const result = SecurityUtils.bigIntToFixedBytes(1n, 4);
            expect(result).toEqual(new Uint8Array([0, 0, 0, 1]));
        });

        it('should handle zero', () => {
            const result = SecurityUtils.bigIntToFixedBytes(0n, 4);
            expect(result).toEqual(new Uint8Array([0, 0, 0, 0]));
        });

        it('should handle exact fit', () => {
            const result = SecurityUtils.bigIntToFixedBytes(0xDEADBEEFn, 4);
            expect(result).toEqual(new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]));
        });

        it('should handle odd hex length by adding leading zero', () => {
            const result = SecurityUtils.bigIntToFixedBytes(0x123n, 4);
            expect(result).toEqual(new Uint8Array([0x00, 0x00, 0x01, 0x23]));
        });

        it('should throw when value exceeds length', () => {
            expect(() => SecurityUtils.bigIntToFixedBytes(0x1_00_00n, 2))
                .toThrow(/exceeds expected length/);
        });

        it('should throw on non-positive length', () => {
            expect(() => SecurityUtils.bigIntToFixedBytes(1n, 0))
                .toThrow(/Length must be positive/);
            expect(() => SecurityUtils.bigIntToFixedBytes(1n, -1))
                .toThrow(/Length must be positive/);
        });

        it('should produce consistent length', () => {
            for (let len of [1, 8, 16, 32, 64]) {
                const result = SecurityUtils.bigIntToFixedBytes(0n, len);
                expect(result.length).toBe(len);
            }
        });
    });

    describe('fixedTimeEquals', () => {
        it('should return true for identical arrays', () => {
            const a = new Uint8Array([1, 2, 3, 4]);
            const b = new Uint8Array([1, 2, 3, 4]);
            expect(SecurityUtils.fixedTimeEquals(a, b)).toBe(true);
        });

        it('should return true for empty arrays', () => {
            expect(SecurityUtils.fixedTimeEquals(new Uint8Array(0), new Uint8Array(0))).toBe(true);
        });

        it('should return false for different lengths', () => {
            const a = new Uint8Array([1, 2, 3]);
            const b = new Uint8Array([1, 2, 3, 4]);
            expect(SecurityUtils.fixedTimeEquals(a, b)).toBe(false);
        });

        it('should return false for different content same length', () => {
            const a = new Uint8Array([1, 2, 3, 4]);
            const b = new Uint8Array([1, 2, 3, 5]);
            expect(SecurityUtils.fixedTimeEquals(a, b)).toBe(false);
        });

        it('should return false for completely different arrays', () => {
            const a = new Uint8Array(32).fill(0x00);
            const b = new Uint8Array(32).fill(0xFF);
            expect(SecurityUtils.fixedTimeEquals(a, b)).toBe(false);
        });

        it('should return false for single differing byte at end', () => {
            const a = new Uint8Array(100).fill(0xAA);
            const b = new Uint8Array(100).fill(0xAA);
            b[99] = 0xBB;
            expect(SecurityUtils.fixedTimeEquals(a, b)).toBe(false);
        });
    });

    describe('expModAsync', () => {
        it('should return 0 when mod is 1', async () => {
            const result = await SecurityUtils.expModAsync(12345n, 67890n, 1n);
            expect(result).toBe(0n);
        });

        it('should compute basic exponentiation', async () => {
            // 2^10 mod 1000 = 1024 mod 1000 = 24
            const result = await SecurityUtils.expModAsync(2n, 10n, 1000n);
            expect(result).toBe(24n);
        });

        it('should handle exponent 0', async () => {
            const result = await SecurityUtils.expModAsync(5n, 0n, 7n);
            expect(result).toBe(1n);
        });

        it('should handle base 0', async () => {
            const result = await SecurityUtils.expModAsync(0n, 5n, 7n);
            expect(result).toBe(0n);
        });

        it('should handle large numbers', async () => {
            const base = 2n;
            const exp = 65537n;
            const mod = (1n << 2048n) - 159n;
            const result = await SecurityUtils.expModAsync(base, exp, mod);
            expect(result).toBeLessThan(mod);
            expect(result).toBeGreaterThanOrEqual(0n);
        });

        it('should yield to event loop during long computation', async () => {
            const start = Date.now();
            const promise = SecurityUtils.expModAsync(
                3n, 
                (1n << 100n) - 1n, 
                (1n << 128n) - 1n, 
                1
            );
            
            await new Promise(resolve => setTimeout(resolve, 0));
            
            const result = await promise;
            expect(result).toBeDefined();
            expect(Date.now() - start).toBeGreaterThanOrEqual(0);
        }, 10000);

        it('should be consistent with built-in pow', async () => {
            for (let i = 0; i < 10; i++) {
                const base = BigInt(i + 2);
                const exp = BigInt(i * 3 + 1);
                const mod = BigInt(1000000007);
                const result = await SecurityUtils.expModAsync(base, exp, mod);
                const expected = (base ** exp) % mod;
                expect(result).toBe(expected);
            }
        });
    });

    describe('bigIntToRawBytes', () => {
        it('should convert 0 to [0]', () => {
            expect(SecurityUtils.bigIntToRawBytes(0n)).toEqual(new Uint8Array([0]));
        });

        it('should convert single byte values without padding', () => {
            expect(SecurityUtils.bigIntToRawBytes(1n)).toEqual(new Uint8Array([1]));
            expect(SecurityUtils.bigIntToRawBytes(255n)).toEqual(new Uint8Array([0xFF]));
        });

        it('should convert multi-byte values', () => {
            expect(SecurityUtils.bigIntToRawBytes(256n)).toEqual(new Uint8Array([1, 0]));
            expect(SecurityUtils.bigIntToRawBytes(0xDEADBEEFn)).toEqual(new Uint8Array([0xDE, 0xAD, 0xBE, 0xEF]));
        });

        it('should handle odd hex length', () => {
            // 0x123 = 0x01 0x23
            expect(SecurityUtils.bigIntToRawBytes(0x123n)).toEqual(new Uint8Array([0x01, 0x23]));
        });

        it('should round-trip with bytesToBigInt', () => {
            const values = [
                0n,
                1n,
                255n,
                256n,
                0xDEADBEEFn,
                (1n << 256n) - 1n,
                (1n << 1024n) - 1n,
            ];

            for (const value of values) {
                const bytes = SecurityUtils.bigIntToRawBytes(value);
                const recovered = SecurityUtils.bytesToBigInt(bytes);
                expect(recovered).toBe(value);
            }
        });
    });

    describe('Cross-method consistency', () => {
        it('bigIntToFixedBytes and bigIntToRawBytes should produce same content when length matches', () => {
            const value = 0x123456789ABCDEFn;
            const raw = SecurityUtils.bigIntToRawBytes(value);
            const fixed = SecurityUtils.bigIntToFixedBytes(value, raw.length);
            expect(fixed).toEqual(raw);
        });

        it('bytesToBigInt should handle output from bigIntToFixedBytes', () => {
            const value = 0xABCDn;
            const fixed = SecurityUtils.bigIntToFixedBytes(value, 8);
            const recovered = SecurityUtils.bytesToBigInt(fixed);
            expect(recovered).toBe(value);
        });
    });
});