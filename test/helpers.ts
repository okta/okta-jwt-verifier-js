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

import OktaJwtVerifier, { type VerifierOptions } from '../src/index.ts';

export const ISSUER = 'https://foo.okta.com/oauth2/default';
export const KID = 'test-kid';

const b64u = (input: string | ArrayBuffer): string =>
  Buffer.from(typeof input === 'string' ? input : new Uint8Array(input)).toString('base64url');

const ALG = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } as const;

export type TestKey = { privateKey: CryptoKey, jwk: Record<string, unknown> };

export async function generateKey (kid = KID): Promise<TestKey> {
  const { privateKey, publicKey } = await crypto.subtle.generateKey(
    { ...ALG, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) }, true, ['sign', 'verify']
  );
  const jwk = await crypto.subtle.exportKey('jwk', publicKey);
  return { privateKey, jwk: { ...jwk, kid, alg: 'RS256', use: 'sig' } };
}

export const defaultKey = await generateKey();
export const otherKey = await generateKey();

/** Signs a token. `header` overrides are merged into the default `{ alg: 'RS256', kid }` header. */
export async function createToken (
  claims: Record<string, unknown>,
  header: Record<string, unknown> = {},
  key: TestKey = defaultKey
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const head = b64u(JSON.stringify({ alg: 'RS256', kid: KID, ...header }));
  const body = b64u(JSON.stringify({ iat: now, exp: now + 3600, ...claims }));
  const signature = await crypto.subtle.sign(ALG, key.privateKey, Buffer.from(`${head}.${body}`));
  return `${head}.${body}.${b64u(signature)}`;
}

export const jwksResponse = (...keys: TestKey[]) =>
  new Response(JSON.stringify({ keys: keys.map(k => k.jwk) }), { status: 200 });

/** Creates a verifier whose keys are supplied by `getKeysInterceptor` (no network). */
export function createVerifier (options: Partial<VerifierOptions> = {}): OktaJwtVerifier {
  return new OktaJwtVerifier({
    issuer: ISSUER,
    getKeysInterceptor: async () => [defaultKey.jwk],
    ...options
  });
}
