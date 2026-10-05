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

import { JWT, JWTError, DefaultIDTokenValidator } from '@okta/auth-foundation';
import { ConfigurationValidationError } from './errors.ts';
import { createFetchImplementation } from './fetch.ts';
import { JwksLoader } from './jwks.ts';
import {
  assertClientId,
  verifyAssertedClaims,
  verifyAudience,
  verifyClientId,
  verifyNonce,
  verifyIssuer,
  type Claims,
  type ExpectedAudience
} from './claims.ts';
import { assertIssuer, assertNoRemovedOptions, type VerifierOptions } from './options.ts';

export type { VerifierOptions, ExpectedAudience };
export { ConfigurationValidationError, JWT };

const SUPPORTED_ALG = 'RS256';

export default class OktaJwtVerifier {
  readonly claimsToAssert: Claims;
  readonly issuer: string;
  readonly jwksUri: string;
  readonly #clientId?: string;
  readonly #testing: VerifierOptions['testing'];
  readonly #jwks: JwksLoader;

  constructor (options: VerifierOptions = {} as VerifierOptions) {
    // Assert configuration options exist and are well-formed (not necessarily correct!)
    assertNoRemovedOptions(options);
    assertIssuer(options.issuer, options.testing);
    if (options.clientId) {
      assertClientId(options.clientId);
    }

    this.claimsToAssert = options.assertClaims || {};
    this.issuer = options.issuer;
    this.jwksUri = options.jwksUri ? options.jwksUri : options.issuer + '/v1/keys';
    this.#clientId = options.clientId;
    this.#testing = options.testing;
    this.#jwks = new JwksLoader({
      jwksUri: this.jwksUri,
      fetchImpl: createFetchImplementation(options),
      getKeysInterceptor: options.getKeysInterceptor,
    });
  }

  /**
   * Verifies signature (RS256 only), `exp` and `nbf`. Shared by access and ID token verification.
   */
  async #verifyJwt (tokenString: string): Promise<JWT> {
    const jwt = new JWT(tokenString);

    if (jwt.header.alg !== SUPPORTED_ALG) {
      throw new JWTError(`Unsupported jwt signing algorithm: ${jwt.header.alg}`);
    }
    if (!jwt.header.kid) {
      throw new JWTError('No KID specified');
    }

    let verified: boolean;
    try {
      verified = await jwt.verifySignature(await this.#jwks.getKeys());
    } catch (err) {
      if (!(err instanceof JWTError && err.message === 'No public key found')) {
        throw err;
      }
      // key set may be stale (key rotation), retry once with a fresh key set
      verified = await jwt.verifySignature(await this.#jwks.refresh());
    }
    if (!verified) {
      throw new JWTError('Signature verification failed');
    }

    const now = Date.now() / 1000;
    const { exp, nbf } = jwt.claims;
    if (typeof exp === 'number' && exp <= now) {
      throw new JWTError('Jwt is expired');
    }
    if (typeof nbf === 'number' && nbf > now) {
      throw new JWTError('Jwt not active yet');
    }

    return jwt;
  }

  /**
   * Primary method for resource servers: verifies an access token.
   * Checks signature, expiration, audience, issuer and any `assertClaims`.
   */
  async verifyAccessToken (accessTokenString: string, expectedAudience?: ExpectedAudience): Promise<JWT> {
    const jwt = await this.#verifyJwt(accessTokenString);
    verifyAudience(expectedAudience, jwt.claims.aud);
    verifyIssuer(this.issuer, jwt.claims.iss);
    verifyAssertedClaims(this.claimsToAssert, jwt.claims);
    return jwt;
  }

  /**
   * Verifies an ID token. ID tokens are intended for the client that initiated authentication;
   * do NOT use them to authorize requests to a resource server. Use `verifyAccessToken` for that.
   */
  async verifyIdToken (idTokenString: string, expectedClientId?: string, expectedNonce?: string): Promise<JWT> {
    const jwt = await this.#verifyJwt(idTokenString);
    // these keep v4 semantics (e.g. a token containing a nonce requires the caller to pass one)
    verifyClientId(expectedClientId, jwt.claims.aud);
    verifyIssuer(this.issuer, jwt.claims.iss);
    verifyNonce(expectedNonce, jwt.claims.nonce);
    // OIDC ID token validation: issuer, audience, scheme, exp, iat, nonce, ...
    DefaultIDTokenValidator.validate(jwt, new URL(this.issuer), expectedClientId as string, {
      nonce: expectedNonce,
      allowHTTP: !!this.#testing?.disableHttpsCheck,
    });
    verifyAssertedClaims(this.claimsToAssert, jwt.claims);
    return jwt;
  }
}
