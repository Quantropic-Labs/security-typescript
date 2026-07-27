/**
 * Cryptographic utility functions: Base64, BigInteger conversion, constant-time comparison, modular exponentiation.
 */
export class SecurityUtils {

  /** Encodes Uint8Array to standard Base64. */
  static toBase64(bytes: Uint8Array): string {
    let binary = '';

    for (let i = 0; i < bytes.length; i++) 
      binary += String.fromCharCode(bytes[i]);

    return btoa(binary);
  }

  /** Decodes URL-safe or standard Base64 to Uint8Array. */
  static fromBase64(base64: string): Uint8Array {
    let cleaned = base64.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
    const mod = cleaned.length % 4;

    if (mod !== 0) {
      cleaned += '='.repeat(4 - mod);
    }

    const binary = atob(cleaned);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++)
      bytes[i] = binary.charCodeAt(i);

    return bytes;
  }

  /** Converts big-endian bytes to bigint. */
  static bytesToBigInt(bytes: Uint8Array): bigint {
    if (bytes.length === 0)
       return 0n;

    return BigInt('0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''));
  }

  /** Converts bigint to fixed-length big-endian bytes (pads only; never truncates). */
  static bigIntToFixedBytes(bn: bigint, length: number): Uint8Array {
    if (length <= 0) 
      throw new Error("Length must be positive.");
    
    let hex = bn.toString(16);
    
    if (hex.length % 2 !== 0)
      hex = '0' + hex;
    
    const byteLength = hex.length / 2;
    
    if (byteLength > length)
        throw new Error(`Value byte length (${byteLength}) exceeds expected length (${length}). Possible data corruption or context mismatch.`);
      
    hex = hex.padStart(length * 2, '0');
    
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    
    return bytes;
  }

  /** Constant-time comparison of two Uint8Arrays. */
  static fixedTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) 
      return false;

    let diff = 0;

    for (let i = 0; i < a.length; i++) 
      diff |= a[i] ^ b[i];
    return diff === 0;
  }
  
  /**
   * Async modular exponentiation with event-loop yielding.
   * @param yieldEvery — number of iterations before yielding (default 64).
   */
  static async expModAsync(
      base: bigint, 
      exp: bigint, 
      mod: bigint, 
      yieldEvery: number = 64
  ): Promise<bigint> {
      if (mod === 1n) return 0n;
      let res = 1n;
      base = base % mod;
      let i = 0;

      while (exp > 0n) {
          if ((exp & 1n) === 1n)
              res = (res * base) % mod;
          exp >>= 1n;
          if (exp > 0n)
              base = (base * base) % mod;

          if (++i % yieldEvery === 0) {
              await new Promise<void>(resolve => setTimeout(resolve, 0));
          }
      }
      return res;
  }

  static bigIntToRawBytes(bn: bigint): Uint8Array {
    if (bn === 0n) 
      return new Uint8Array([0]);
    
    let hex = bn.toString(16);
    if (hex.length % 2 !== 0)
      hex = '0' + hex;
    
    return new Uint8Array(hex.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
  }
}