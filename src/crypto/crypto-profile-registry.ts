import { AesGcmOptions } from "./aes-gcm-options.js";
import { CryptoProfile } from "./crypto-profile.js";
import { CryptoVersion } from "./crypto-version.js";
import { KdfOptions } from "./kdf-options.js";

/**
 * Registry of predefined {@link CryptoProfile} instances by version.
 * Returns a fresh profile per call.
 */
export class CryptoProfileRegistry {
    static getProfile(version: CryptoVersion): CryptoProfile {
        switch (version) {
            case CryptoVersion.V1:
                return new CryptoProfile({
                    version: CryptoVersion.V1,
                    kdfOptions: KdfOptions.V1,
                    aesGcmOptions: AesGcmOptions.V1,
                });
            default:
                throw new Error(`Unsupported crypto version: ${version}`);
        }
    }

     /** Latest supported profile (currently V1). */
    static get latest(): CryptoProfile {
        return this.getProfile(CryptoVersion.V1);
    }
}