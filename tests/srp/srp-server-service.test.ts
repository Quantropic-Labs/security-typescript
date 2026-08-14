import { describe, it, expect } from 'vitest';
import { SrpServerService, type SrpSessionState } from '../../src/srp/srp-server-service.js';
import { SrpClientService } from '../../src/srp/srp-client-service.js';
import { SrpContextFactory } from '../../src/srp/srp-context-factory.js';
import { SrpGroup } from '../../src/srp/srp-group.js';
import { SecurityUtils } from '../../src/utils/security.utils.js';

describe('SrpServerService', () => {
    const srpServer = new SrpServerService();
    const validGroup = SrpGroup.Rfc5054_3072;

    async function getCtx() {
        return await SrpContextFactory.create(validGroup);
    }

    function validSalt(): Uint8Array {
        return crypto.getRandomValues(new Uint8Array(16));
    }

    async function validVerifier(): Promise<Uint8Array> {
        const ctx = await getCtx();
        const hash = crypto.getRandomValues(new Uint8Array(32));
        const x = SecurityUtils.bytesToBigInt(hash);
        const v = await SecurityUtils.expModAsync(ctx.g, x, ctx.N);
        return SecurityUtils.bigIntToFixedBytes(v, ctx.modulusSize);
    }

    async function createDummyState(): Promise<SrpSessionState> {
        const ctx = await getCtx();
        const dummyB = crypto.getRandomValues(new Uint8Array(ctx.modulusSize));
        return {
            login: 'alice',
            privateKeyB: new Uint8Array(32),
            verifier: await validVerifier(),
            publicKeyB: dummyB,
            salt: validSalt(),
        };
    }

    describe('getSrpChallenge', () => {
        it('should throw on null verifier', async () => {
            await expect(srpServer.getSrpChallenge('alice', null as unknown as Uint8Array, validSalt(), validGroup))
                .rejects.toThrow(/Verifier cannot be null|verifier is corrupted/);
        });

        it('should throw on null login', async () => {
            const v = await validVerifier();
            await expect(srpServer.getSrpChallenge(null as unknown as string, v, validSalt(), validGroup))
                .rejects.toThrow(/Login cannot be null/);
        });

        it('should throw on empty login', async () => {
            const v = await validVerifier();
            await expect(srpServer.getSrpChallenge('', v, validSalt(), validGroup))
                .rejects.toThrow(/Login cannot be null/);
        });

        it('should throw on zero verifier', async () => {
            const ctx = await getCtx();
            const zeroV = new Uint8Array(ctx.modulusSize);
            await expect(srpServer.getSrpChallenge('alice', zeroV, validSalt(), validGroup))
                .rejects.toThrow(/corrupted/);
        });

        it('should throw on verifier equal to modulus', async () => {
            const ctx = await getCtx();
            const nBytes = SecurityUtils.bigIntToFixedBytes(ctx.N, ctx.modulusSize);
            await expect(srpServer.getSrpChallenge('alice', nBytes, validSalt(), validGroup))
                .rejects.toThrow(/corrupted/);
        });

        it('should return state with non-zero B for valid inputs', async () => {
            const salt = validSalt();
            const verifier = await validVerifier();
            const state = await srpServer.getSrpChallenge('alice', verifier, salt, validGroup);

            expect(state.login).toBe('alice');
            expect(state.salt).toEqual(salt);
            expect(state.verifier).toEqual(verifier);
            expect(state.privateKeyB.length).toBeGreaterThan(0);
            expect(state.publicKeyB.length).toBeGreaterThan(0);
        });
    });

    describe('verifySrpProof', () => {
        it('should throw on invalid A Base64', async () => {
            const state = await createDummyState();
            await expect(srpServer.verifySrpProof(state, '!!!', 'AA==', validGroup))
                .rejects.toThrow();
        });

        it('should throw when A is zero', async () => {
            const state = await createDummyState();
            await expect(srpServer.verifySrpProof(state, 'AA==', 'AA==', validGroup))
                .rejects.toThrow(/Incorrect value of A|Invalid A/);
        });

        it('should throw on corrupted verifier in state', async () => {
            const ctx = await getCtx();
            const state: SrpSessionState = {
                login: 'alice',
                privateKeyB: new Uint8Array(32),
                verifier: new Uint8Array(ctx.modulusSize),
                publicKeyB: new Uint8Array(ctx.modulusSize),
                salt: validSalt(),
            };
            await expect(srpServer.verifySrpProof(state, 'AA==', 'AA==', validGroup))
                .rejects.toThrow(/corrupted/);
        });

        it('should throw on wrong M1', async () => {
            const salt = validSalt();
            const verifier = await validVerifier();
            const state = await srpServer.getSrpChallenge('alice', verifier, salt, validGroup);
            const ctx = await getCtx();

            const fakeM1 = crypto.getRandomValues(new Uint8Array(ctx.hashSize));
            await expect(
                srpServer.verifySrpProof(state, SecurityUtils.toBase64(state.publicKeyB), SecurityUtils.toBase64(fakeM1), validGroup)
            ).rejects.toThrow(/Invalid password/);
        });

        it('should return M2 for valid client proof (full handshake)', async () => {
            const client = new SrpClientService();
            const salt = validSalt();
            const saltB64 = SecurityUtils.toBase64(salt);

            const authHash = crypto.getRandomValues(new Uint8Array(32));
            const verifierB64 = await client.generateSrpVerifier(SecurityUtils.toBase64(authHash), validGroup);
            const verifierBytes = SecurityUtils.fromBase64(verifierB64);

            const state = await srpServer.getSrpChallenge('alice', verifierBytes, salt, validGroup);
            const bB64 = SecurityUtils.toBase64(state.publicKeyB);

            const { A, M1, SessionKeyK } = await client.generateSrpProof('alice', authHash, saltB64, bB64, validGroup);

            const m2 = await srpServer.verifySrpProof(state, A, M1, validGroup);
            expect(m2).toBeTruthy();

            const clientAccepts = await client.verifyServerM2(A, M1, SessionKeyK, m2, validGroup);
            expect(clientAccepts).toBe(true);
        });
    });
});