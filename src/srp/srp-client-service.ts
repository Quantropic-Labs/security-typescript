import { KeyDerivationService } from "../crypto/key-derivation.service.js";
import { SecurityUtils } from "../utils/security.utils.js";
import { SrpEncoding } from "../utils/srp-encoding.js";
import { SrpContext } from "./srp-context.js";

/**
 * Client-side SRP-6a implementation: proof generation, verifier creation, server M2 verification.
 */
export class SrpClientService {
  private readonly keyDerivation = new KeyDerivationService();

   /**
   * Computes SRP verifier v = g^x mod N from the authentication hash.
   * @param authHash - Auth hash (Base64).
   * @param ctx - SRP context (N, g, hash algorithm, etc.).
   * @returns Verifier as Base64 string.
   */
  async generateSrpVerifier(authHash: string, ctx: SrpContext): Promise<string> {
    const x = SecurityUtils.bytesToBigInt(SecurityUtils.fromBase64(authHash));
    const v = SecurityUtils.expMod(ctx.g, x, ctx.N);
    return SecurityUtils.toBase64(SrpEncoding.toModulusBytes(ctx, v));
  }

  /**
   * Generates client proof (A, M1, session key S) from server challenge.
   * @param login - User login.
   * @param password - Plaintext password.
   * @param saltBase64 - Server salt (standard Base64).
   * @param B_base64 - Server public ephemeral B (standard Base64).
   * @param ctx - SRP context.
   * @returns Object with A and M1 as standard Base64; SessionKeyK as raw bytes.
   */
  async generateSrpProof(login: string, password: string, saltBase64: string, B_base64: string, ctx: SrpContext): Promise<{ A: string; M1: string; SessionKeyK: Uint8Array }> {
    const salt = SecurityUtils.fromBase64(saltBase64);

    const authHash = await this.keyDerivation.deriveAuthHashForSrp(login, password, salt, ctx.hashAlgorithmName);
    const x = SecurityUtils.bytesToBigInt(authHash);

    const privateKeySize = Math.max(32, Math.floor(ctx.modulusSize / 2));
    let aBytes: Uint8Array;
    let a: bigint;

    do {
        aBytes = crypto.getRandomValues(new Uint8Array(privateKeySize));
        a = SecurityUtils.bytesToBigInt(aBytes);
    } while (a === 0n);

    const A = SecurityUtils.expMod(ctx.g, a, ctx.N);
    if (A <= 0n || A >= ctx.N)
        throw new Error('Invalid client public key A.');

    const B = SecurityUtils.bytesToBigInt(SecurityUtils.fromBase64(B_base64));
    if (B % ctx.N === 0n || B >= ctx.N)
      throw new Error('Critical error: B % N === 0');

    const u = await SrpEncoding.hashModuli(ctx, A, B);
    if (u === 0n)
      throw new Error('Недопустимое значение u');

    const gX = SecurityUtils.expMod(ctx.g, x, ctx.N);
    const term = (ctx.k * gX) % ctx.N;
    const base = (B - term + ctx.N) % ctx.N;
    const exponent = a + (u * x);
    const S = SecurityUtils.expMod(base, exponent, ctx.N);

    if (S === 0n)
      throw new Error('Critical error: S === 0');

    const sessionKeyK = await SrpEncoding.computeSessionKey(ctx, S);
    const M1 = await SrpEncoding.computeM1(ctx, A, B, sessionKeyK, login, salt);

    return {
      A: SecurityUtils.toBase64(SrpEncoding.toModulusBytes(ctx, A)),
      M1: SecurityUtils.toBase64(M1),
      SessionKeyK: sessionKeyK
    };
  }

  /**
   * Validates the server proof M2 to authenticate the server.
   * @param A_b64 - Client public A (Base64).
   * @param M1_b64 - Client proof M1 (Base64).
   * @param S_b64 - Session key S (Base64).
   * @param serverM2_b64 - Server proof M2 (Base64).
   * @param ctx - SRP context.
   * @returns True if the server proof is valid.
   */

  async verifyServerM2(A_b64: string, M1_b64: string, sessionKeyK: Uint8Array, serverM2_b64: string, ctx: SrpContext): Promise<boolean> {
      const A = SecurityUtils.bytesToBigInt(SecurityUtils.fromBase64(A_b64));
      const M1 = SecurityUtils.fromBase64(M1_b64);  // уже Uint8Array
      const computedM2 = await SrpEncoding.computeM2(ctx, A, M1, sessionKeyK);
      const serverM2Bytes = SecurityUtils.fromBase64(serverM2_b64);
      return SecurityUtils.fixedTimeEquals(computedM2, serverM2Bytes);
  }
}