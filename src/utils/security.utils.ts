export class SecurityUtils {
    static readonly MODULUS_SIZE : number = 384;
    static readonly NONCE_SIZE : number = 12;
    static readonly TAG_SIZE : number = 16;
    static readonly KEY_SIZE : number = 32;

    static readonly N : bigint = BigInt("0xAC6BDB41324A9A9BF166DE5E1F403D434A6E1B3B94A7E62AC1211858E002C75AD4455C9D19C0A3180296917A376205164043E20144FF485719D181A99EB574671AC58054457ED444A67032EA17D03AD43464D2397449CA593630A670D90D95A78E846A3C8AF80862098D80F33C42ED7059E75225E0A52718E2379369F65B79680A6560B080092EE71986066735A96A7D42E7597116742B02D3A154471B6A23D84E0D642C790D597A2BB7F5A48F734898BDD138C69493E723491959C1B4BD40C91C1C7924F88D046467A006507E781220A80C55A927906A7C6C9C227E674686DD5D1B855D28F0D604E24586C608630B9A34C4808381A54F0D9080A5F90B60187F");
    static readonly g : bigint = BigInt(2);
    static readonly k : bigint = BigInt("0xD55AE1AEC9F9115621E93E16E5DE4517DF8450D0957024D1256AA32B71E4E412");

    /*                          
        Base64 helpers
    */

    static toBase64(bytes: Uint8Array): string {
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++)
            binary += String.fromCharCode(bytes[i]);

        return window.btoa(binary);
    }

    static fromBase64(base64: string): Uint8Array {
        const cleaned = base64.replace(/-/g, '+').replace(/_/g, '/').replace(/\s/g, '');
        const binary = window.atob(cleaned);
        const bytes = new Uint8Array(binary.length);

        for (let i = 0; i < binary.length; i++)
             bytes[i] = binary.charCodeAt(i);

        return bytes;
    }

    /*                          
        BigInt helpers
    */

    static bytesToBigInt = (bytes: Uint8Array): bigint =>  BigInt('0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''));

    static bigIntToFixedBytes(bn: bigint, length: number): Uint8Array {
        let hex = bn.toString(16);

        if (hex.length % 2 !== 0) 
            hex = '0' + hex;

        if (hex.length > length * 2) 
            throw new Error(`Значение слишком велико для ${length} байт`);
        
        hex = hex.padStart(length * 2, '0');

        return this.fromHex(hex);
    }

    private static fromHex(hex: string): Uint8Array {
        const matches = hex.match(/.{1,2}/g);
        return new Uint8Array(matches ? matches.map(byte => parseInt(byte, 16)) : []);
    }  

    /*                          
        Math
    */  
   
    static expMod(base: bigint, exp: bigint, mod: bigint): bigint {
        let res = BigInt(1);
        base = base % mod;

        while (exp > 0) {
        if (exp % BigInt(2) === BigInt(1)) res = (res * base) % mod;
        base = (base * base) % mod;
        exp = exp / BigInt(2);
        }

        return res;
    }

    /*                          
        SRP helper
    */ 
   static async hashAsPerSrp6a(items: { value: bigint; length: number }[]): Promise<bigint> {
        const buffers = items.map(({ value, length }) => this.bigIntToFixedBytes(value, length));
        const totalLen = buffers.reduce((sum, buf) => sum + buf.length, 0);
        const combined = new Uint8Array(totalLen);

        let offset = 0;

        for (const buf of buffers) {
            combined.set(buf, offset);
            offset += buf.length;
        }

        const hash = await crypto.subtle.digest('SHA-256', combined);

        return this.bytesToBigInt(new Uint8Array(hash));
    }
}