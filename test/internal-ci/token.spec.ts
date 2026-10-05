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
import OktaJwtVerifier from '../../src/index.ts';
import { constants, getAccessToken, getIdToken, getKeySet, createForgedToken, type TokenParams } from '../live.ts';

// These tests make LIVE requests to an Okta org (see testenv) and run in a resource-constrained CI environment
const LONG_TIMEOUT = 15000;
const { ISSUER, CLIENT_ID, USERNAME, PASSWORD, REDIRECT_URI } = constants;
const NONCE = 'foo';
const expectedAud = 'api://default';

const tokenParams: TokenParams = { ISSUER, CLIENT_ID, USERNAME, PASSWORD, REDIRECT_URI, NONCE };
const createVerifier = (options = {}) => new OktaJwtVerifier({
  issuer: ISSUER,
  testing: { disableHttpsCheck: !!process.env.OKTA_TESTING_DISABLEHTTPSCHECK },
  ...options
});

describe('Access token test with api call', () => {
  const verifier = createVerifier();

  it('should allow me to verify Okta access tokens', async () => {
    const jwt = await verifier.verifyAccessToken(await getAccessToken(tokenParams), expectedAud);
    expect(jwt.claims.iss).toBe(ISSUER);
  }, LONG_TIMEOUT);

  it('should fail if the signature is invalid', async () => {
    const jwt = await verifier.verifyAccessToken(await getAccessToken(tokenParams), expectedAud);
    const forged = await createForgedToken(jwt.claims, { kid: jwt.header.kid });
    await expect(verifier.verifyAccessToken(forged, expectedAud)).rejects.toThrow();
  }, LONG_TIMEOUT);

  it('should fail if no kid is present in the JWT header', async () => {
    const jwt = await verifier.verifyAccessToken(await getAccessToken(tokenParams), expectedAud);
    const token = await createForgedToken(jwt.claims, { kid: undefined });
    await expect(verifier.verifyAccessToken(token, expectedAud)).rejects.toThrow('No KID specified');
  }, LONG_TIMEOUT);

  it('should fail if the kid cannot be found', async () => {
    const jwt = await verifier.verifyAccessToken(await getAccessToken(tokenParams), expectedAud);
    const token = await createForgedToken(jwt.claims, { kid: 'foo' });
    await expect(verifier.verifyAccessToken(token, expectedAud)).rejects.toThrow('No public key found');
  }, LONG_TIMEOUT);

  it('should fail if the token is expired (exp)', async () => {
    const accessToken = await getAccessToken(tokenParams);
    const jwt = await verifier.verifyAccessToken(accessToken, expectedAud);
    const spy = jest.spyOn(Date, 'now').mockReturnValue(((jwt.claims.exp as number) + 1) * 1000);
    try {
      await expect(verifier.verifyAccessToken(accessToken, expectedAud)).rejects.toThrow(/expired/i);
    } finally {
      spy.mockRestore();
    }
  }, LONG_TIMEOUT);

  it('should allow me to assert custom claims', async () => {
    const v = createVerifier({ assertClaims: { cid: 'baz', foo: 'bar' } });
    await expect(v.verifyAccessToken(await getAccessToken(tokenParams), expectedAud)).rejects.toThrow(
      `claim 'cid' value '${CLIENT_ID}' does not match expected value 'baz', ` +
      "claim 'foo' value 'undefined' does not match expected value 'bar'"
    );
  }, LONG_TIMEOUT);

  it('should only fetch the jwks once for repeated verifications', async () => {
    const fetchSpy = jest.fn<typeof fetch>((input, init) => fetch(input, init));
    const v = createVerifier({ fetchImpl: fetchSpy });
    const accessToken = await getAccessToken(tokenParams);
    await v.verifyAccessToken(accessToken, expectedAud);
    await v.verifyAccessToken(accessToken, expectedAud);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  }, LONG_TIMEOUT);
});

describe('ID token tests with api calls', () => {
  const verifier = createVerifier();

  it('should allow me to verify Okta ID tokens', async () => {
    const jwt = await verifier.verifyIdToken(await getIdToken(tokenParams), CLIENT_ID, NONCE);
    expect(jwt.claims.iss).toBe(ISSUER);
  }, LONG_TIMEOUT);

  it('should fail if the signature is invalid', async () => {
    const jwt = await verifier.verifyIdToken(await getIdToken(tokenParams), CLIENT_ID, NONCE);
    const forged = await createForgedToken(jwt.claims, { kid: jwt.header.kid });
    await expect(verifier.verifyIdToken(forged, CLIENT_ID, NONCE)).rejects.toThrow();
  }, LONG_TIMEOUT);

  it('should use getKeysInterceptor', async () => {
    const getKeysInterceptor = jest.fn(async () => (await getKeySet()).keys);
    const v = createVerifier({ getKeysInterceptor });
    const jwt = await v.verifyIdToken(await getIdToken(tokenParams), CLIENT_ID, NONCE);
    expect(getKeysInterceptor).toHaveBeenCalled();
    expect(jwt.claims.iss).toBe(ISSUER);
  }, LONG_TIMEOUT);

  it('should use getKeysInterceptor, but fall back to the jwks uri', async () => {
    const getKeysInterceptor = jest.fn(async () => []);
    const v = createVerifier({ getKeysInterceptor });
    const jwt = await v.verifyIdToken(await getIdToken(tokenParams), CLIENT_ID, NONCE);
    expect(getKeysInterceptor).toHaveBeenCalled();
    expect(jwt.claims.iss).toBe(ISSUER);
  }, LONG_TIMEOUT);
});
