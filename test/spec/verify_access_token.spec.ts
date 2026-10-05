/*!
 * Copyright (c) 2017-Present, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

import { JWT } from '@okta/auth-foundation';
import { createToken, createVerifier, otherKey, ISSUER } from '../helpers.ts';

const AUD = 'http://myapp.com/';
const claims = { aud: AUD, iss: ISSUER };
const rejects = async (p: Promise<unknown>, message: string) => {
  await expect(p).rejects.toThrow(new Error(message));
};

describe('Jwt Verifier - Verify Access Token', () => {
  describe('signature and standard claims', () => {
    it('passes if the signature is valid and returns a JWT', async () => {
      const token = await createToken(claims);
      const jwt = await createVerifier().verifyAccessToken(token, AUD);
      expect(jwt).toBeInstanceOf(JWT);
      expect(jwt.claims.aud).toBe(AUD);
      expect(jwt.toString()).toBe(token);
    });

    it('fails if the signature is invalid', async () => {
      const token = await createToken(claims, {}, otherKey);
      await rejects(createVerifier().verifyAccessToken(token, AUD), 'Signature verification failed');
    });

    it('fails if the payload was tampered with', async () => {
      const [h, , s] = (await createToken(claims)).split('.');
      const forged = Buffer.from(JSON.stringify({ ...claims, aud: 'evil' })).toString('base64url');
      await rejects(createVerifier().verifyAccessToken(`${h}.${forged}.${s}`, 'evil'), 'Signature verification failed');
    });

    it.each(['HS256', 'none', 'RS512'])('fails if the header alg is %s', async (alg) => {
      const token = await createToken(claims, { alg });
      await rejects(createVerifier().verifyAccessToken(token, AUD), `Unsupported jwt signing algorithm: ${alg}`);
    });

    it('fails if no kid is specified', async () => {
      const token = await createToken(claims, { kid: undefined });
      await rejects(createVerifier().verifyAccessToken(token, AUD), 'No KID specified');
    });

    it('fails if the kid is not in the key set', async () => {
      const token = await createToken(claims, { kid: 'unknown' });
      await rejects(createVerifier().verifyAccessToken(token, AUD), 'No public key found');
    });

    it('fails if the token is expired', async () => {
      const now = Math.floor(Date.now() / 1000);
      const token = await createToken({ ...claims, iat: now - 3600, exp: now - 10 });
      await rejects(createVerifier().verifyAccessToken(token, AUD), 'Jwt is expired');
    });

    it('fails if the token is not yet active', async () => {
      const token = await createToken({ ...claims, nbf: Math.floor(Date.now() / 1000) + 600 });
      await expect(createVerifier().verifyAccessToken(token, AUD)).rejects.toThrow(/nbf/);
    });

    it('passes if nbf is in the past', async () => {
      const token = await createToken({ ...claims, nbf: Math.floor(Date.now() / 1000) - 600 });
      await createVerifier().verifyAccessToken(token, AUD);
    });

    // KNOWN ISSUE in @okta/auth-foundation 0.9.0: the JWT constructor throws unless now > nbf + clockTolerance,
    // so a token that becomes valid "now" cannot be parsed. Remove \`.failing\` once fixed upstream.
    it.failing('passes if nbf is just now (nbf === iat)', async () => {
      const now = Math.floor(Date.now() / 1000);
      const token = await createToken({ ...claims, iat: now, nbf: now });
      await createVerifier().verifyAccessToken(token, AUD);
    });

    it('fails for a malformed token', async () => {
      await expect(createVerifier().verifyAccessToken('not-a-jwt', AUD)).rejects.toThrow();
    });

    it('fails if iss claim does not match verifier issuer', async () => {
      const token = await createToken({ ...claims, iss: 'not-the-issuer' });
      await rejects(
        createVerifier().verifyAccessToken(token, AUD),
        `issuer not-the-issuer does not match expected issuer: ${ISSUER}`
      );
    });
  });

  describe('audience', () => {
    const verify = async (aud: unknown, expected?: string | string[]) =>
      createVerifier().verifyAccessToken(await createToken({ ...claims, aud }), expected);

    it('fails when no audience expectation is passed', async () => {
      await rejects(verify('http://any-aud.com/'), 'expected audience is required');
    });

    it('passes when given an audience matching expectation string', async () => {
      await verify(AUD, AUD);
    });

    it('passes when given an audience matching expectation array', async () => {
      await verify(AUD, ['one', AUD, 'three']);
    });

    it('passes when aud is an array containing the expectation', async () => {
      await verify([AUD, 'one'], AUD);
    });

    it('passes when aud is an array and matches an expectation array', async () => {
      await verify([AUD, 'one'], ['two', AUD]);
    });

    it('fails when aud is an array that does not include the expectation', async () => {
      await rejects(verify([AUD, 'one'], 'two'), `audience claims ${AUD}, one do not include expected audience: two`);
    });

    it('fails when aud is an array with no match in the expectation array', async () => {
      await rejects(
        verify([AUD, 'one'], ['two, three']),
        `audience claims ${AUD}, one do not match one of the expected audiences: two, three`
      );
    });

    it('fails with an invalid audience', async () => {
      await rejects(
        verify('http://wrong-aud.com/', AUD),
        `audience claim http://wrong-aud.com/ does not match expected audience: ${AUD}`
      );
    });

    it('fails with an invalid audience when given an array of expectations', async () => {
      await rejects(
        verify('http://wrong-aud.com/', ['one', AUD, 'three']),
        `audience claim http://wrong-aud.com/ does not match one of the expected audiences: one, ${AUD}, three`
      );
    });

    it('fails when given an empty array of audience expectations', async () => {
      await rejects(
        verify('http://any-aud.com/', []),
        'audience claim http://any-aud.com/ does not match one of the expected audiences: '
      );
    });
  });

  describe('assertClaims', () => {
    const verify = async (assertClaims: Record<string, unknown>, extra: Record<string, unknown>) =>
      createVerifier({ assertClaims }).verifyAccessToken(await createToken({ ...claims, ...extra }), AUD);

    it('should only allow includes operator for custom claims', async () => {
      await rejects(
        verify({ 'groups.blarg': 'Everyone' }, { groups: ['Everyone'] }),
        "operator: 'blarg' invalid. Supported operators: 'includes'."
      );
    });

    it('passes exact match', async () => {
      await verify({ sub: 'me' }, { sub: 'me' });
    });

    it('fails exact mismatch', async () => {
      await rejects(verify({ sub: 'me' }, { sub: 'you' }), "claim 'sub' value 'you' does not match expected value 'me'");
    });

    it('includes: flat expectation, array claim', async () => {
      const jwt = await verify({ 'groups.includes': 'Everyone' }, { groups: ['Everyone', 'Another'] });
      expect(jwt.claims.groups).toEqual(['Everyone', 'Another']);
    });

    it('includes: flat expectation, flat claim', async () => {
      const jwt = await verify({ 'scp.includes': 'promos:read' }, { scp: 'promos:read promos:write' });
      expect(jwt.claims.scp).toBe('promos:read promos:write');
    });

    it('includes: fails for flat expectation, array claim', async () => {
      await rejects(
        verify({ 'groups.includes': 'Yet Another' }, { groups: ['Everyone', 'Another'] }),
        "claim 'groups' value 'Everyone,Another' does not include expected value 'Yet Another'"
      );
    });

    it('includes: fails for flat expectation, flat claim', async () => {
      await rejects(
        verify({ 'scp.includes': 'promos:delete' }, { scp: 'promos:read promos:write' }),
        "claim 'scp' value 'promos:read promos:write' does not include expected value 'promos:delete'"
      );
    });

    it('includes: array expectation, array claim', async () => {
      await verify({ 'groups.includes': ['Everyone', 'Yet Another'] }, { groups: ['Everyone', 'Another', 'Yet Another'] });
    });

    it('includes: array expectation, flat claim', async () => {
      await verify({ 'scp.includes': ['promos:read', 'promos:delete'] }, { scp: 'promos:read promos:write promos:delete' });
    });

    it('includes: fails for array expectation, array claim', async () => {
      await rejects(
        verify({ 'groups.includes': ['Yet Another'] }, { groups: ['Everyone', 'Another'] }),
        "claim 'groups' value 'Everyone,Another' does not include expected value 'Yet Another'"
      );
    });

    it('includes: fails for array expectation, flat claim', async () => {
      await rejects(
        verify({ 'scp.includes': ['promos:delete'] }, { scp: 'promos:read promos:write' }),
        "claim 'scp' value 'promos:read promos:write' does not include expected value 'promos:delete'"
      );
    });
  });
});
