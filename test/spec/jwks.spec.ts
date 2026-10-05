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
import { JwksLoader } from '../../src/jwks.ts';
import { createToken, generateKey, jwksResponse, defaultKey, ISSUER } from '../helpers.ts';

const claims = { aud: 'api://default', iss: ISSUER };

describe('JWKS loading', () => {
  afterEach(() => { jest.useRealTimers(); });

  const setup = (responses: () => Response) => {
    const fetchImpl = jest.fn<typeof fetch>(async () => responses());
    const verifier = new OktaJwtVerifier({ issuer: ISSUER, fetchImpl });
    return { fetchImpl, verifier };
  };

  it('fetches keys from the issuer jwks uri', async () => {
    const { fetchImpl, verifier } = setup(() => jwksResponse(defaultKey));
    await verifier.verifyAccessToken(await createToken(claims), claims.aud);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(fetchImpl.mock.calls[0][0]).toBe(`${ISSUER}/v1/keys`);
  });

  it('caches keys between verifications', async () => {
    const { fetchImpl, verifier } = setup(() => jwksResponse(defaultKey));
    await verifier.verifyAccessToken(await createToken(claims), claims.aud);
    await verifier.verifyAccessToken(await createToken(claims), claims.aud);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('coalesces concurrent fetches', async () => {
    const { fetchImpl, verifier } = setup(() => jwksResponse(defaultKey));
    const token = await createToken(claims);
    await Promise.all([1, 2, 3].map(() => verifier.verifyAccessToken(token, claims.aud)));
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('re-fetches once the cache ttl expires', async () => {
    const fetchImpl = jest.fn<typeof fetch>(async () => jwksResponse(defaultKey));
    const loader = new JwksLoader({ jwksUri: 'https://foo/keys', cacheTtl: 1000, fetchImpl });
    const now = jest.spyOn(Date, 'now');

    now.mockReturnValue(0);
    await loader.getKeys();
    now.mockReturnValue(500);
    await loader.getKeys();
    expect(fetchImpl).toHaveBeenCalledTimes(1);

    now.mockReturnValue(1500);
    await loader.getKeys();
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('refreshes once when the kid is not in the cached key set, then succeeds', async () => {
    const rotated = await generateKey('rotated-kid');
    let current = defaultKey;
    const fetchImpl = jest.fn<typeof fetch>(async () => jwksResponse(current));
    const verifier = new OktaJwtVerifier({ issuer: ISSUER, fetchImpl });
    await verifier.verifyAccessToken(await createToken(claims), claims.aud);
    expect(fetchImpl).toHaveBeenCalledTimes(1);

    // key rotation on the server; forced refresh is subject to a cooldown, so move time forward
    current = rotated;
    const spy = jest.spyOn(Date, 'now').mockReturnValue(Date.now() + 60 * 1000);
    const token = await createToken(claims, { kid: 'rotated-kid' }, rotated);
    await verifier.verifyAccessToken(token, claims.aud);
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    spy.mockRestore();
  });

  it('does not fetch on every unknown kid (cooldown)', async () => {
    const { fetchImpl, verifier } = setup(() => jwksResponse(defaultKey));
    const unknown = await createToken(claims, { kid: 'nope' });
    await expect(verifier.verifyAccessToken(unknown, claims.aud)).rejects.toThrow('No public key found');
    await expect(verifier.verifyAccessToken(unknown, claims.aud)).rejects.toThrow('No public key found');
    await expect(verifier.verifyAccessToken(unknown, claims.aud)).rejects.toThrow('No public key found');
    // initial load only; refreshes are suppressed by the cooldown
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('rejects a non-ok response', async () => {
    const { verifier } = setup(() => new Response('nope', { status: 500 }));
    await expect(verifier.verifyAccessToken(await createToken(claims), claims.aud))
      .rejects.toThrow(/Unable to fetch JWKS .* HTTP 500/);
  });

  it('rejects a malformed jwks document', async () => {
    const { verifier } = setup(() => new Response(JSON.stringify({ keys: [{ nope: true }] })));
    await expect(verifier.verifyAccessToken(await createToken(claims), claims.aud))
      .rejects.toThrow(/Unexpected JWKS response/);
  });

  it('uses getKeysInterceptor instead of fetching', async () => {
    const fetchImpl = jest.fn<typeof fetch>();
    const verifier = new OktaJwtVerifier({ issuer: ISSUER, fetchImpl, getKeysInterceptor: async () => [defaultKey.jwk] });
    await verifier.verifyAccessToken(await createToken(claims), claims.aud);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('falls back to fetching when getKeysInterceptor returns no keys', async () => {
    const fetchImpl = jest.fn<typeof fetch>(async () => jwksResponse(defaultKey));
    const verifier = new OktaJwtVerifier({ issuer: ISSUER, fetchImpl, getKeysInterceptor: async () => [] });
    await verifier.verifyAccessToken(await createToken(claims), claims.aud);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('passes the dispatcher through to fetch', async () => {
    const dispatcher: any = {};
    const fetchImpl = jest.fn<typeof fetch>(async () => jwksResponse(defaultKey));
    const verifier = new OktaJwtVerifier({ issuer: ISSUER, fetchImpl, dispatcher });
    await verifier.verifyAccessToken(await createToken(claims), claims.aud);
    expect((fetchImpl.mock.calls[0][1] as any).dispatcher).toBe(dispatcher);
  });
});
