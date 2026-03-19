import { KeyDerivationService } from '../crypto/index.js';
import { SecurityUtils } from '../utils/index.js';

export class SrpService {
  private readonly keyDerivation = new KeyDerivationService();

  async generateSrpVerifier(authHash: string): Promise<string> {
    const x = SecurityUtils.bytesToBigInt(SecurityUtils.fromBase64(authHash));
    const v = SecurityUtils.expMod(SecurityUtils.g, x, SecurityUtils.N);
    return SecurityUtils.toBase64(SecurityUtils.bigIntToFixedBytes(v, SecurityUtils.MODULUS_SIZE));
  }

  async generateSrpProof(login: string, password: string, saltBase64: string, B_base64: string): Promise<{ A: string; M1: string; S: string }> {
    const salt = SecurityUtils.fromBase64(saltBase64);
    const { authHash } = await this.keyDerivation.deriveKeysFromPassword(login, password, salt);
    const x = SecurityUtils.bytesToBigInt(SecurityUtils.fromBase64(authHash));

    const aBytes = crypto.getRandomValues(new Uint8Array(32));
    const a = SecurityUtils.bytesToBigInt(aBytes);

    const A = SecurityUtils.expMod(SecurityUtils.g, a, SecurityUtils.N);
    if (A % SecurityUtils.N === 0n) 
        throw new Error('Критическая ошибка: A % N === 0');

    const B = SecurityUtils.bytesToBigInt(SecurityUtils.fromBase64(B_base64));
    if (B % SecurityUtils.N === 0n) 
        throw new Error('Критическая ошибка: B % N === 0');

    const u = await SecurityUtils.hashAsPerSrp6a([
      { value: A, length: SecurityUtils.MODULUS_SIZE },
      { value: B, length: SecurityUtils.MODULUS_SIZE },
    ]);
    if (u === 0n) 
        throw new Error('Недопустимое значение u');

    const gX = SecurityUtils.expMod(SecurityUtils.g, x, SecurityUtils.N);
    const term = (SecurityUtils.k * gX) % SecurityUtils.N;
    const base = (B - term + SecurityUtils.N) % SecurityUtils.N;
    const exponent = a + (u * x);
    const S = SecurityUtils.expMod(base, exponent, SecurityUtils.N);

    if (S === 0n) 
        throw new Error('Критическая ошибка: S === 0');

    const M1 = await SecurityUtils.hashAsPerSrp6a([
      { value: A, length: SecurityUtils.MODULUS_SIZE },
      { value: B, length: SecurityUtils.MODULUS_SIZE },
      { value: S, length: SecurityUtils.MODULUS_SIZE },
    ]);

    return {
      A: SecurityUtils.toBase64(SecurityUtils.bigIntToFixedBytes(A, SecurityUtils.MODULUS_SIZE)),
      M1: SecurityUtils.toBase64(SecurityUtils.bigIntToFixedBytes(M1, 32)),
      S: SecurityUtils.toBase64(SecurityUtils.bigIntToFixedBytes(S, SecurityUtils.MODULUS_SIZE)),
    };
  }

  async verifyServerM2(A_b64: string, M1_b64: string, S_b64: string, serverM2_b64: string): Promise<boolean> {
    const A = SecurityUtils.bytesToBigInt(SecurityUtils.fromBase64(A_b64));
    const M1 = SecurityUtils.bytesToBigInt(SecurityUtils.fromBase64(M1_b64));
    const S = SecurityUtils.bytesToBigInt(SecurityUtils.fromBase64(S_b64));

    const computedM2 = await SecurityUtils.hashAsPerSrp6a([
      { value: A, length: SecurityUtils.MODULUS_SIZE },
      { value: M1, length: 32 },
      { value: S, length: SecurityUtils.MODULUS_SIZE },
    ]);
    const computedM2_b64 = SecurityUtils.toBase64(SecurityUtils.bigIntToFixedBytes(computedM2, 32));

    return serverM2_b64 === computedM2_b64;
  }
}