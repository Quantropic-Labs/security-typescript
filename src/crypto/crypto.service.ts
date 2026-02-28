import { SecurityUtils } from '../utils/index'

export class CryptoService {

  async encryptData<T>(dataModel: T, key: Uint8Array): Promise<string> {
    const encoder = new TextEncoder();
    let jsonString: string;
    if (dataModel instanceof Uint8Array) {
      jsonString = `"${SecurityUtils.toBase64(dataModel)}"`;
    } else {
      jsonString = JSON.stringify(dataModel);
    }
    const plainBytes = encoder.encode(jsonString);
    const nonce = crypto.getRandomValues(new Uint8Array(SecurityUtils.NONCE_SIZE));

    const cryptoKey = await crypto.subtle.importKey(
      'raw', 
      key as BufferSource, 
      'AES-GCM', 
      false, 
      ['encrypt']);

    const encryptedContent = await crypto.subtle.encrypt({ 
        name: 'AES-GCM',
        iv: nonce, 
        tagLength: SecurityUtils.TAG_SIZE * 8},
        cryptoKey,
         plainBytes
    );

    const result = new Uint8Array(SecurityUtils.NONCE_SIZE + encryptedContent.byteLength);
    result.set(nonce, 0);
    result.set(new Uint8Array(encryptedContent), SecurityUtils.NONCE_SIZE);
    
    return SecurityUtils.toBase64(result);
  }

  async decryptedData<T>(encryptedBase64: string, key: Uint8Array): Promise<T | null>{
    if (!encryptedBase64) 
        return null;

    const encryptedBytes = SecurityUtils.fromBase64(encryptedBase64);

    if (encryptedBytes.length < SecurityUtils.NONCE_SIZE + SecurityUtils.TAG_SIZE)
        throw new Error('Недопустимый формат зашифрованных данных');

    const nonce = encryptedBytes.slice(0, SecurityUtils.NONCE_SIZE);
    const ciphertextWithTag = encryptedBytes.slice(SecurityUtils.NONCE_SIZE);

    const cryptoKey = await crypto.subtle.importKey(
        'raw',
         key as BufferSource, 
         'AES-GCM', 
         false,
          ['decrypt']);

    try {
      const decryptedBuffer = await crypto.subtle.decrypt({ 
        name: 'AES-GCM',
        iv: nonce,
        tagLength: 
        SecurityUtils.TAG_SIZE * 8
     },
      cryptoKey,
      ciphertextWithTag);

      const decoder = new TextDecoder();
      const jsonString = decoder.decode(decryptedBuffer);

      return JSON.parse(jsonString) as T;
    } catch (e) {
      console.error('Ошибка дешифрования:', e);
      return null;
    }
  }

  generateRandomBytes = (length = 32): Uint8Array => crypto.getRandomValues(new Uint8Array(length));
}