import { SecurityUtils } from "../utils/security.utils.js";
import { SrpEncoding } from "../utils/srp-encoding.js";
import { SrpContext } from "./srp-context.js";

/**
 * Server-side SRP session state containing ephemeral keys and verifier.
 */
export interface SrpSessionState {
  /** User login identifier. */
  login: string;

  /** Server private ephemeral key (Base64). */
  privateKeyB: Uint8Array;

  /** Password verifier (Base64). */
  verifier: Uint8Array;

  /** Server public ephemeral key B (Base64). */
  publicKeyB: Uint8Array;

  /** User salt s (needed for RFC 5054 M1). */
  salt: Uint8Array;
}

/**
 * Server-side SRP-6a: challenge generation, client proof verification, server proof creation.
 */
export class SrpServerService {

  /**
   * Generates server challenge B and session state from verifier.
   * @param login - User login.
   * @param verifierBytes - Stored verifier v as byte array.
   * @param ctx - SRP context (hash, N, g, etc.).
   * @returns Session state with private b, verifier, and public B.
   */
  async getSrpChallenge(login: string, verifierBytes: Uint8Array, salt: Uint8Array, ctx: SrpContext): Promise<SrpSessionState> {
    if (!login || login.trim().length === 0)
      throw new Error('Login cannot be null or empty.');
    
    if (!verifierBytes || verifierBytes.length === 0)
      throw new Error('Verifier cannot be null or empty.');  
    
    const v = SecurityUtils.bytesToBigInt(verifierBytes);
    
    if (v <= 0n || v >= ctx.N)
      throw new Error("The verifier is corrupted");
    
    const privateKeySize = Math.max(32, Math.floor(ctx.modulusSize / 2));

    while (true) {
        const bBytes = crypto.getRandomValues(new Uint8Array(privateKeySize));
        const b = SecurityUtils.bytesToBigInt(bBytes);

        if (b === 0n) {
            continue;
        }

        const gB = SecurityUtils.expMod(ctx.g, b, ctx.N);
        const B = (ctx.k * v + gB) % ctx.N;

        if (B !== 0n) {
            return {
                login,
                privateKeyB: bBytes,
                verifier: verifierBytes,
                publicKeyB: SrpEncoding.toModulusBytes(ctx, B),
                salt
            };
        }
    }
  }

  /**
   * Verifies client M1 proof and returns server M2 proof.
   * @param sessionState - Server session state.
   * @param a - Client public A (Base64).
   * @param m1 - Client proof M1 (Base64).
   * @param ctx - SRP context.
   * @returns Server proof M2 as Base64 string.
   * @throws If verification fails or input is invalid.
   */
  async verifySrpProof(sessionState: SrpSessionState, a: string, m1: string, ctx: SrpContext): Promise<string> {
    const A = SecurityUtils.bytesToBigInt(SecurityUtils.fromBase64(a));
    const M1_client = SecurityUtils.fromBase64(m1);
    const b = SecurityUtils.bytesToBigInt(sessionState.privateKeyB);
    const v = SecurityUtils.bytesToBigInt(sessionState.verifier);
    const B = SecurityUtils.bytesToBigInt(sessionState.publicKeyB);

    if (v <= 0n || v >= ctx.N)
      throw new Error("The verifier is corrupted");

    if (A % ctx.N === 0n)
      throw new Error("Incorrect value of A");

    if (A <= 0n || A >= ctx.N)
      throw new Error("Invalid A (out of range)");

    if (B <= 0n || B >= ctx.N)
        throw new Error("Invalid server public key B.");

    const u = await SrpEncoding.hashModuli(ctx, A, B);

    if (u === 0n)
      throw new Error("Error in calculating the parameter u");

    const vU = SecurityUtils.expMod(v, u, ctx.N);
    const S = SecurityUtils.expMod((A * vU) % ctx.N, b, ctx.N);
    
    if (S === 0n)
      throw new Error("Critical error: shared secret S is zero (possible malicious A).");

    const sessionKeyK = await SrpEncoding.computeSessionKey(ctx, S);
    const M1_server = await SrpEncoding.computeM1(ctx, A, B, sessionKeyK, sessionState.login, sessionState.salt);

    if (!SecurityUtils.fixedTimeEquals(M1_server, M1_client))
      throw new Error("Invalid password");

    const M2_server = await SrpEncoding.computeM2(ctx, A, M1_client, sessionKeyK);

    return SecurityUtils.toBase64(M2_server);
  }
}