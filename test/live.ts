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

// Helpers for tests that make LIVE requests to an Okta org (test/internal-ci). Not used by unit tests.
import { createRequire } from 'node:module';
import { generateKey, createToken as signToken, type TestKey } from './helpers.ts';

const require = createRequire(import.meta.url);
export const constants = require('./oidc.config.cjs')({ port: 8080 }).spaConstants as Record<string, string>;

export type TokenParams = Record<'ISSUER' | 'CLIENT_ID' | 'REDIRECT_URI' | 'USERNAME' | 'PASSWORD' | 'NONCE', string>;

async function getTokens (options: TokenParams & { RESPONSE_TYPE?: string }) {
  const { ISSUER, CLIENT_ID, REDIRECT_URI, USERNAME, PASSWORD, NONCE, RESPONSE_TYPE } = options;
  const domain = new URL(ISSUER).origin;
  const authn = await fetch(`${domain}/api/v1/authn`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: USERNAME, password: PASSWORD })
  });
  if (!authn.ok) {
    throw new Error(`/api/v1/authn returned error: ${authn.status}`);
  }
  const { sessionToken } = await authn.json() as { sessionToken?: string };
  if (!sessionToken) {
    throw new Error('Could not get sessionToken from /api/v1/authn');
  }

  const params = new URLSearchParams({
    sessionToken,
    response_type: RESPONSE_TYPE || 'id_token token',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'openid',
    state: 'foo',
    nonce: NONCE || 'foo'
  });
  const authorize = await fetch(`${ISSUER}/v1/authorize?${params}`, { redirect: 'manual' });
  if (authorize.status >= 400) {
    throw new Error(`/api/v1/authorize error: ${authorize.status}`);
  }
  const location = new URL(authorize.headers.get('location') as string);
  const result = new URLSearchParams(location.hash ? location.hash.slice(1) : location.search);
  if (result.get('error')) {
    throw new Error(`/api/v1/authorize error in query: ${result.get('error')}`);
  }
  return { accessToken: result.get('access_token'), idToken: result.get('id_token') };
}

export async function getAccessToken (options: TokenParams): Promise<string> {
  const { accessToken } = await getTokens({ ...options, RESPONSE_TYPE: 'token' });
  if (!accessToken) {
    throw new Error('Could not parse access token from URI');
  }
  return accessToken;
}

export async function getIdToken (options: TokenParams): Promise<string> {
  const { idToken } = await getTokens({ ...options, RESPONSE_TYPE: 'id_token' });
  if (!idToken) {
    throw new Error('Could not parse ID token from URI');
  }
  return idToken;
}

export async function getKeySet (): Promise<{ keys: unknown[] }> {
  const response = await fetch(`${constants.ISSUER}/v1/keys`);
  if (!response.ok) {
    throw new Error('Failed to get keys');
  }
  return response.json() as Promise<{ keys: unknown[] }>;
}

/** Re-signs claims with a locally generated key (NOT the org's key), so verification must fail */
let wrongKey: TestKey;
export async function createForgedToken (claims: Record<string, unknown>, header: Record<string, unknown> = {}) {
  wrongKey ??= await generateKey('forged');
  return signToken(claims, header, wrongKey);
}
