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

  /** Computes M1 = H(A || B || sessionKeyK). */
  static async computeM1(ctx: SrpContext, A: bigint, B: bigint, sessionKeyK: Uint8Array): Promise<Uint8Array> {
      return this.computeHash(
          ctx.hashAlgorithmName,
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
    const sBytes = this.toModulusBytes(ctx, S);
    const hashBuffer = await crypto.subtle.digest(
        ctx.hashAlgorithmName, 
        sBytes as BufferSource
    );
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