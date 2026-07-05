import { HashAlgorithm } from "../crypto/hash-algorithm.js";
import { SrpContext } from "../srp/srp-context.js";
import { SecurityUtils } from "./security.utils.js";

/**
 * SRP-specific serialization and hashing utilities.
 */
export class SrpEncoding {

  /** Serializes a bigint to modulus-sized big-endian bytes. */
  static toModulusBytes(ctx: SrpContext, value: bigint): Uint8Array {
    return SecurityUtils.bigIntToFixedBytes(value, ctx.modulusSize);
  }

  /** Serializes a bigint to hash-sized big-endian bytes. */
  static toHashBytes(ctx: SrpContext, value: bigint): Uint8Array {
    return SecurityUtils.bigIntToFixedBytes(value, ctx.hashSize);
  }

  /** Hashes modulus-sized values (e.g., u = H(A, B)). */
  static async hashModuli(ctx: SrpContext, ...values: bigint[]): Promise<bigint> {
    const buffers = values.map(v => this.toModulusBytes(ctx, v));
    return this.hash(ctx.hashAlgorithmName, ...buffers);
  }

  /**
  * Computes the client proof M1 = H( H(N) ⊕ H(g) | H(I) | s | PAD(A) | PAD(B) | K ).
  * 
  * Follows RFC 5054 / SRP-6a:
  * - H(N) and H(g) are hashed as modulus-sized values.
  * - Identity (I) is hashed as raw UTF-8 bytes.
  * - A and B are padded to the modulus size before hashing.
  * - K is the session key (H(S) without padding).
  * 
  * @param ctx - SRP context containing N, g, hash algorithm, and modulus size.
  * @param A - Client ephemeral public key.
  * @param B - Server ephemeral public key.
  * @param sessionKeyK - Session key K as raw bytes.
  * @param identity - User identity (login). Should already be normalized (trimmed / lowercased) by the caller.
  * @param salt - User-specific salt bytes.
  * @returns The M1 proof as raw hash bytes.
  */
  static async computeM1(
      ctx: SrpContext, 
      A: bigint, 
      B: bigint, 
      sessionKeyK: Uint8Array, 
      identity: string, 
      salt: Uint8Array
  ): Promise<Uint8Array> {
    // H(N) and H(g) — hashed as modulus-sized values
    const nBytes = this.toModulusBytes(ctx, ctx.N);
    const gBytes = this.toModulusBytes(ctx, ctx.g);

    const hashN = await this.computeHash(ctx.hashAlgorithmName, nBytes);
    const hashG = await this.computeHash(ctx.hashAlgorithmName, gBytes);

    // H(N) ⊕ H(g)
    const xorNg = new Uint8Array(hashN.length);
    for (let i = 0; i < hashN.length; i++)
        xorNg[i] = hashN[i] ^ hashG[i];

    // H(I) — identity hashed as UTF-8
    const encoder = new TextEncoder();
    const hashI = await this.computeHash(ctx.hashAlgorithmName, encoder.encode(identity));

    // Final hash: H( H(N)⊕H(g) | H(I) | s | PAD(A) | PAD(B) | K )
    return this.computeHash(
      ctx.hashAlgorithmName,
      xorNg,
      hashI,
      salt,
      this.toModulusBytes(ctx, A),
      this.toModulusBytes(ctx, B),
      sessionKeyK
    );
  }
  
  /** Computes M2 = H(A || M1 || sessionKeyK). */
  static async computeM2(ctx: SrpContext, A: bigint, m1Bytes: Uint8Array, sessionKeyK: Uint8Array): Promise<Uint8Array> {
      return this.computeHash(
          ctx.hashAlgorithmName,
          this.toModulusBytes(ctx, A),
          m1Bytes,
          sessionKeyK
      );
  }
  
  /** Computes session key K = H(S). */
  static async computeSessionKey(ctx: SrpContext, S: bigint): Promise<Uint8Array> {
      let hex = S.toString(16);
      if (hex.length % 2 !== 0)
        hex = '0' + hex;
      const sBytes = new Uint8Array(hex.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
      const hashBuffer = await crypto.subtle.digest(ctx.hashAlgorithmName, sBytes);
      return new Uint8Array(hashBuffer);
  }

/** Hashes bytes and returns raw Uint8Array (для M1/M2). */
private static async computeHash(algo: HashAlgorithm, ...buffers: Uint8Array[]): Promise<Uint8Array> {
    const totalLen = buffers.reduce((sum, b) => sum + b.length, 0);
    const combined = new Uint8Array(totalLen);
    let offset = 0;
    for (const buf of buffers) { combined.set(buf, offset); offset += buf.length; }
    const hashBuffer = await crypto.subtle.digest(algo, combined);
    return new Uint8Array(hashBuffer);
}

/** Concatenates byte arrays and returns the hash as bigint. */
private static async hash(algo: HashAlgorithm, ...buffers: Uint8Array[]): Promise<bigint> {
    const totalLen = buffers.reduce((sum, b) => sum + b.length, 0);
    const combined = new Uint8Array(totalLen);
    let offset = 0;
    for (const buf of buffers) { combined.set(buf, offset); offset += buf.length; }
    const hashBuffer = await crypto.subtle.digest(algo, combined);
    return SecurityUtils.bytesToBigInt(new Uint8Array(hashBuffer));
  }
}