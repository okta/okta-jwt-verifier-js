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

import { jest } from '@jest/globals';
import { JWT } from '@okta/auth-foundation';
import { createToken, createVerifier, otherKey, ISSUER } from '../helpers.ts';

const CLIENT_ID = '0oaoesxtxmPf08QHk0h7';
const claims = { aud: CLIENT_ID, iss: ISSUER };
const rejects = async (p: Promise<unknown>, message: string | RegExp) => {
  await expect(p).rejects.toThrow(message instanceof RegExp ? message : new Error(message));
};

describe('Jwt Verifier - Verify ID Token', () => {
  describe('basic validation', () => {
    it('passes if the signature is valid and returns a JWT', async () => {
      const token = await createToken(claims);
      const jwt = await createVerifier().verifyIdToken(token, CLIENT_ID);
      expect(jwt).toBeInstanceOf(JWT);
      expect(jwt.claims.aud).toBe(CLIENT_ID);
    });

    it('fails if the signature is invalid', async () => {
      const token = await createToken(claims, {}, otherKey);
      await rejects(createVerifier().verifyIdToken(token, CLIENT_ID), 'Signature verification failed');
    });

    it('fails if iss claim does not match verifier issuer', async () => {
      const token = await createToken({ ...claims, iss: 'not-the-issuer' });
      await rejects(
        createVerifier().verifyIdToken(token, CLIENT_ID),
        `issuer not-the-issuer does not match expected issuer: ${ISSUER}`
      );
    });

    it('fails when no client id expectation is passed', async () => {
      await rejects(createVerifier().verifyIdToken(await createToken(claims)), 'expected client id is required');
    });

    it('fails with an audience that does not match the client id', async () => {
      const token = await createToken({ ...claims, aud: 'wrong_client_id' });
      await rejects(
        createVerifier().verifyIdToken(token, CLIENT_ID),
        `audience claim wrong_client_id does not match expected client id: ${CLIENT_ID}`
      );
    });

    it('fails with an invalid client id', async () => {
      await rejects(
        createVerifier().verifyIdToken(await createToken(claims), '{clientId}'),
        /Replace {clientId} with the client ID of your Application/
      );
    });

    it('fails if the token is expired', async () => {
      const now = Math.floor(Date.now() / 1000);
      const token = await createToken({ ...claims, iat: now - 3600, exp: now - 10 });
      await rejects(createVerifier().verifyIdToken(token, CLIENT_ID), 'Jwt is expired');
    });

    it('fails if iat is outside the grace interval', async () => {
      const now = Math.floor(Date.now() / 1000);
      const token = await createToken({ ...claims, iat: now - 1800, exp: now + 1800 });
      await rejects(createVerifier().verifyIdToken(token, CLIENT_ID), /issuedAtTime/);
    });

    it('allows a non-https issuer when the https check is disabled', async () => {
      jest.spyOn(console, 'warn').mockImplementation(() => {});
      const issuer = 'http://foo.okta.com/oauth2/default';
      const token = await createToken({ ...claims, iss: issuer });
      const verifier = createVerifier({ issuer, testing: { disableHttpsCheck: true } });
      await verifier.verifyIdToken(token, CLIENT_ID);
    });
  });

  describe('nonce', () => {
    it('fails when the token has a nonce but none is expected', async () => {
      const token = await createToken({ ...claims, nonce: 'foo' });
      await rejects(createVerifier().verifyIdToken(token, CLIENT_ID), 'expected nonce is required');
    });

    it('fails when a nonce is expected but the claim is missing', async () => {
      await rejects(
        createVerifier().verifyIdToken(await createToken(claims), CLIENT_ID, 'some'),
        'nonce claim is missing but expected: some'
      );
    });

    it('passes when the nonce matches', async () => {
      await createVerifier().verifyIdToken(await createToken({ ...claims, nonce: 'foo' }), CLIENT_ID, 'foo');
    });

    it('fails when the nonce does not match', async () => {
      await rejects(
        createVerifier().verifyIdToken(await createToken({ ...claims, nonce: 'foo' }), CLIENT_ID, 'bar'),
        'nonce claim foo does not match expected nonce: bar'
      );
    });
  });

  describe('assertClaims', () => {
    it('applies asserted claims', async () => {
      const verifier = createVerifier({ assertClaims: { 'groups.includes': 'Everyone' } });
      const token = await createToken({ ...claims, groups: ['Everyone'] });
      const jwt = await verifier.verifyIdToken(token, CLIENT_ID);
      expect(jwt.claims.groups).toEqual(['Everyone']);
    });

    it('fails when an asserted claim is missing', async () => {
      const verifier = createVerifier({ assertClaims: { 'groups.includes': 'Yet Another' } });
      const token = await createToken({ ...claims, groups: ['Everyone'] });
      await rejects(verifier.verifyIdToken(token, CLIENT_ID), /does not include expected value 'Yet Another'/);
    });
  });

  describe('verified JWT', () => {
    it('exposes claims, header and raw token through getters', async () => {
      const token = await createToken(claims);
      const jwt = await createVerifier().verifyIdToken(token, CLIENT_ID);
      expect(jwt.rawValue).toBe(token);
      expect(jwt.toString()).toBe(token);
      expect(jwt.header.alg).toBe('RS256');
      expect(jwt.issuer).toBe(ISSUER);
    });

    // KNOWN ISSUE in @okta/auth-foundation 0.9.0: \`JWT.isExpired\` is implemented as \`now.isBefore(exp)\`, which is
    // true for a VALID token (inverted). Remove \`.failing\` once fixed upstream.
    it.failing('reports isExpired === false for a valid token', async () => {
      const jwt = await createVerifier().verifyIdToken(await createToken(claims), CLIENT_ID);
      expect(jwt.isExpired).toBe(false);
    });

    it('has no setters for claims', async () => {
      const jwt = await createVerifier().verifyIdToken(await createToken(claims), CLIENT_ID);
      expect(() => { (jwt as any).claims = {}; }).toThrow();
      expect(() => { (jwt as any).header = {}; }).toThrow();
    });
  });
});
