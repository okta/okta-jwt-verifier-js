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

const nock = require('nock');
const tk = require('timekeeper');

const constants = require('../constants')

// These tests involve LIVE network requests and run in a resource-constrained CI environment
const LONG_TIMEOUT = 15000;
const LONG_TIMEOUT_PDV = 50000;

const { getAccessToken, getIdToken, createVerifier, createToken} = require('../util');

// These need to be exported in the environment, from a working Okta org
const ISSUER = constants.ISSUER;
const CLIENT_ID = constants.CLIENT_ID;
const USERNAME = constants.USERNAME;
const PASSWORD = constants.PASSWORD;
const REDIRECT_URI = constants.REDIRECT_URI;
const NONCE = 'foo';

// Used to get an access token and id token from the AS
const issuer1TokenParams = {
  ISSUER,
  CLIENT_ID,
  USERNAME,
  PASSWORD,
  REDIRECT_URI,
  NONCE
};

// JWT_VERIFIER_REPO env var is only set in PDV script
if (process.env.JWT_VERIFIER_REPO) describe.only('Running only PDV tests', () => {
  console.warn('skipping non-PDV tests');
  const expectedAud = 'api://default';
  const expectedClientId = CLIENT_ID;
  const verifier = createVerifier();

  it('should allow me to verify Okta access tokens', () => {
    return getAccessToken(issuer1TokenParams)
    .then(accessToken => verifier.verifyAccessToken(accessToken, expectedAud))
    .then(jwt => {
      expect(jwt.claims.iss).toBe(ISSUER);
    });
  }, LONG_TIMEOUT_PDV);

  it('should allow me to verify Okta ID tokens', () => {
    return getIdToken(issuer1TokenParams)
    .then(idToken => {
      return verifier.verifyIdToken(idToken, expectedClientId, NONCE);
    })
    .then(jwt => {
      expect(jwt.claims.iss).toBe(ISSUER);
    });
  }, LONG_TIMEOUT_PDV);
});

describe('Access token test with api call', () => {
  const expectedAud = 'api://default';
  const verifier = createVerifier();

  it('should allow me to verify Okta access tokens', () => {
    return getAccessToken(issuer1TokenParams)
    .then(accessToken => verifier.verifyAccessToken(accessToken, expectedAud))
    .then(jwt => {
      expect(jwt.claims.iss).toBe(ISSUER);
    });
  }, LONG_TIMEOUT);

  it('should fail if the signature is invalid', () => {
    return getAccessToken(issuer1TokenParams)
    .then(accessToken => verifier.verifyAccessToken(accessToken, expectedAud))
    .then(jwt => {
      // Create an access token with the same claims and kid, then re-sign it with another RSA private key - this should fail
      const token = createToken(jwt.claims, { kid: jwt.header.kid });
      return verifier.verifyAccessToken(token, expectedAud)
      .catch(err => expect(err.message).toBe('Signature verification failed'));
    });
  }, LONG_TIMEOUT);

  it('should fail if no kid is present in the JWT header', () => {
    return getAccessToken(issuer1TokenParams)
    .then(accessToken => verifier.verifyAccessToken(accessToken, expectedAud))
    .then(jwt => {
      // Create an access token that does not have a kid
      const token = createToken(jwt.claims);
      return verifier.verifyAccessToken(token, expectedAud)
      .catch(err => expect(err.message).toBe('Error while resolving signing key for kid "undefined"'));
    });
  }, LONG_TIMEOUT);

  it('should fail if the kid cannot be found', () => {
    return getAccessToken(issuer1TokenParams)
    .then(accessToken => verifier.verifyAccessToken(accessToken, expectedAud))
    .then(jwt => {
      // Create an access token with the same claims but a kid that will not resolve
      const token = createToken(jwt.claims, { kid: 'foo' });
      return verifier.verifyAccessToken(token, expectedAud)
      .catch(err => expect(err.message).toBe('Error while resolving signing key for kid "foo"'));
    });
  }, LONG_TIMEOUT);

  it('should fail if the token is expired (exp)', () => {
    return getAccessToken(issuer1TokenParams)
    .then(accessToken =>
      verifier.verifyAccessToken(accessToken, expectedAud)
      .then(jwt => {
        // Now advance time past the exp claim
        const now = new Date();
        const then = new Date((jwt.claims.exp * 1000) + 1000);
        tk.travel(then);
        return verifier.verifyAccessToken(accessToken, expectedAud)
        .then(() => {
          throw new Error('Should have errored');
        })
        .catch(err => {
          tk.travel(now);
          expect(err.message).toBe('Jwt is expired');
        });
      }));
  }, LONG_TIMEOUT);

  it('should allow me to assert custom claims', () => {
    const verifier = createVerifier({
      assertClaims: {
        cid: 'baz',
        foo: 'bar'
      }
    });
    return getAccessToken(issuer1TokenParams)
    .then(accessToken =>
      verifier.verifyAccessToken(accessToken, expectedAud)
      .catch(err => {
        // Extra debugging for an intermittent issue
        const result = typeof accessToken === 'string' ? 'accessToken is a string' : accessToken;
        expect(result).toBe('accessToken is a string');
        expect(err.message).toBe(
          `claim 'cid' value '${CLIENT_ID}' does not match expected value 'baz', claim 'foo' value 'undefined' does not match expected value 'bar'`
        );
      })
    );
  }, LONG_TIMEOUT);

  it('should cache the jwks for the configured amount of time', () => {
    const verifier = createVerifier({
      cacheMaxAge: 500
    });
    return getAccessToken(issuer1TokenParams)
    .then(accessToken => {
      nock.recorder.rec({
        output_objects: true,
        dont_print: true
      });
      const nockCallObjects = nock.recorder.play();
      return verifier.verifyAccessToken(accessToken, expectedAud)
      .then(jwt => {
        expect(nockCallObjects.length).toBe(1);
        return verifier.verifyAccessToken(accessToken, expectedAud);
      })
      .then(jwt => {
        expect(nockCallObjects.length).toBe(1);
        return new Promise((resolve, reject) => {
          setTimeout(() => {
            verifier.verifyAccessToken(accessToken, expectedAud)
            .then(jwt => {
              expect(nockCallObjects.length).toBe(2);
              resolve();
            })
            .catch(reject);
          }, 1000);
        });
      })
    });
  }, LONG_TIMEOUT);

  it('should rate limit jwks endpoint requests on cache misses', () => {
    const verifier = createVerifier({
      jwksRequestsPerMinute: 2
    });
    return getAccessToken(issuer1TokenParams)
    .then((accessToken => {
      nock.recorder.clear();
      return verifier.verifyAccessToken(accessToken, expectedAud)
      .then(jwt => {
        // Create an access token with the same claims but a kid that will not resolve
        const token = createToken(jwt.claims, { kid: 'foo' });
        return verifier.verifyAccessToken(token, expectedAud)
        .catch(err => verifier.verifyAccessToken(token, expectedAud))
        .catch(err => {
          const nockCallObjects = nock.recorder.play();
          // Expect 1 request for the valid kid, and 1 request for the 2 attempts with an invalid kid
          expect(nockCallObjects.length).toBe(2);
        });
      })
    }));
  });
});

describe('ID token tests with api calls', () => {
  const expectedClientId = CLIENT_ID;
  const verifier = createVerifier();

  it('should allow me to verify Okta ID tokens', () => {
    return getIdToken(issuer1TokenParams)
    .then(idToken => {
      return verifier.verifyIdToken(idToken, expectedClientId, NONCE);
    })
    .then(jwt => {
      expect(jwt.claims.iss).toBe(ISSUER);
    });
  }, LONG_TIMEOUT);

  it('should fail if the signature is invalid', () => {
    return getIdToken(issuer1TokenParams)
    .then(idToken => verifier.verifyIdToken(idToken, expectedClientId, NONCE))
    .then(jwt => {
      // Create an ID token with the same claims and kid, then re-sign it with another RSA private key - this should fail
      const token = createToken(jwt.claims, { kid: jwt.header.kid });
      
      return verifier.verifyIdToken(token, expectedClientId, NONCE)
      .catch(err => expect(err.message).toBe('Signature verification failed'));
    });
  }, LONG_TIMEOUT);

  it('should fail if no kid is present in the JWT header', () => {
    return getIdToken(issuer1TokenParams)
    .then(idToken => verifier.verifyIdToken(idToken, expectedClientId, NONCE))
    .then(jwt => {
      // Create an ID token that does not have a kid
      const token = createToken(jwt.claims);
      return verifier.verifyIdToken(token, expectedClientId, NONCE)
      .catch(err => expect(err.message).toBe('Error while resolving signing key for kid "undefined"'));
    });
  }, LONG_TIMEOUT);

  it('should fail if the kid cannot be found', () => {
    return getIdToken(issuer1TokenParams)
    .then(idToken => verifier.verifyIdToken(idToken, expectedClientId, NONCE))
    .then(jwt => {
      // Create an ID token with the same claims but a kid that will not resolve
      const token = createToken(jwt.claims, { kid: 'foo' });
      return verifier.verifyIdToken(token, expectedClientId, NONCE)
      .catch(err => expect(err.message).toBe('Error while resolving signing key for kid "foo"'));
    });
  }, LONG_TIMEOUT);

  it('should fail if the token is expired (exp)', () => {
    return getIdToken(issuer1TokenParams)
    .then(idToken =>
      verifier.verifyIdToken(idToken, expectedClientId, NONCE)
      .then(jwt => {
        // Now advance time past the exp claim
        const now = new Date();
        const then = new Date((jwt.claims.exp * 1000) + 1000);
        tk.travel(then);
        return verifier.verifyIdToken(idToken, expectedClientId, NONCE)
        .then(() => {
          throw new Error('Should have errored');
        })
        .catch(err => {
          tk.travel(now);
          expect(err.message).toBe('Jwt is expired');
        });
      }));
  }, LONG_TIMEOUT);

  it('should allow me to assert custom claims', () => {
    const verifier = createVerifier({
      assertClaims: {
        aud: 'baz',
        foo: 'bar'
      }
    });
    return getIdToken(issuer1TokenParams)
    .then(idToken =>
      verifier.verifyIdToken(idToken, expectedClientId, NONCE)
      .catch(err => {
        // Extra debugging for an intermittent issue
        const result = typeof idToken === 'string' ? 'idToken is a string' : idToken;
        expect(result).toBe('idToken is a string');
        expect(err.message).toBe(
          `claim 'aud' value '${CLIENT_ID}' does not match expected value 'baz', claim 'foo' value 'undefined' does not match expected value 'bar'`
        );
      })
    );
  }, LONG_TIMEOUT);

  it('should cache the jwks for the configured amount of time', () => {
    const verifier = createVerifier({
      cacheMaxAge: 500
    });
    return getIdToken(issuer1TokenParams)
    .then(idToken => {
      // OKTA-435548: access token and ID token request should not interfere
      nock.recorder.clear();
      nock.restore();
      nock.recorder.rec({
        output_objects: true,
        dont_print: true
      });
      const nockCallObjects = nock.recorder.play();
      return verifier.verifyIdToken(idToken, expectedClientId, NONCE)
      .then(jwt => {
        expect(nockCallObjects.length).toBe(1);
        return verifier.verifyIdToken(idToken, expectedClientId, NONCE);
      })
      .then(jwt => {
        expect(nockCallObjects.length).toBe(1);
        return new Promise((resolve, reject) => {
          setTimeout(() => {
            verifier.verifyIdToken(idToken, expectedClientId, NONCE)
            .then(jwt => {
              expect(nockCallObjects.length).toBe(2);
              resolve();
            })
            .catch(reject);
          }, 1000);
        });
      })
    });
  }, LONG_TIMEOUT);

  it('should rate limit jwks endpoint requests on cache misses', () => {
    const verifier = createVerifier({
      jwksRequestsPerMinute: 2
    });
    return getIdToken(issuer1TokenParams)
    .then((idToken => {
      nock.recorder.clear();
      return verifier.verifyIdToken(idToken, expectedClientId, NONCE)
      .then(jwt => {
        // Create an ID token with the same claims but a kid that will not resolve
        const token = createToken(jwt.claims, { kid: 'foo' });
        return verifier.verifyIdToken(token, expectedClientId, NONCE)
        .catch(err => verifier.verifyIdToken(token, expectedClientId, NONCE))
        .catch(err => {
          const nockCallObjects = nock.recorder.play();
          // Expect 1 request for the valid kid, and 1 request for the 2 attempts with an invalid kid
          expect(nockCallObjects.length).toBe(2);
        });
      })
    }));
  });

}, LONG_TIMEOUT);

