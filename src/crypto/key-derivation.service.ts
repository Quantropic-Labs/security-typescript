import { SecurityUtils } from '../utils';

export class KeyDerivationService{
  readonly ITERATIONS = 600_000;
  readonly KEY_SIZE = 32;

  async deriveKeysFromPassword(login: string, password: string, salt: Uint8Array): Promise<{ kek: Uint8Array; authHash: string }> {
    const safeSalt = new Uint8Array(salt);
    
    const encoder = new TextEncoder();
    const normalizedLogin = login.trim().toLocaleLowerCase();
    const combinedPassword = `${normalizedLogin}:${password}`;
    const passwordBytes = encoder.encode(combinedPassword);
    const baseKey = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits', 'deriveKey']);

    const masterKeyBits = await crypto.subtle.deriveBits({
        name: 'PBKDF2',
        salt: safeSalt, 
        iterations: this.ITERATIONS,
        hash: 'SHA-256'
    }, baseKey, this.KEY_SIZE * 8);

    const masterKey = await crypto.subtle.importKey('raw', masterKeyBits, 'HKDF', false, ['deriveBits']);

    const kek = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: encoder.encode('AES-GCM-KEK-v1') },
      masterKey,
      this.KEY_SIZE * 8
    );

    const authBytes = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: encoder.encode('SERVER-AUTH-HASH-v1') },
      masterKey,
      this.KEY_SIZE * 8
    );

    return {
      kek: new Uint8Array(kek),
      authHash: SecurityUtils.toBase64(new Uint8Array(authBytes)),
    };
  }
}