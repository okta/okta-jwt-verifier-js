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

const { createToken, createVerifier, createCustomClaimsVerifier, rsaKeyPair } = require('../util');

// These need to be exported in the environment, from a working Okta org
const ISSUER = constants.ISSUER;
const CLIENT_ID = constants.CLIENT_ID;
const USERNAME = constants.USERNAME;
const PASSWORD = constants.PASSWORD;
const REDIRECT_URI = constants.REDIRECT_URI;
const NONCE = 'foo';

// Some tests makes LIVE requests using getIdToken(). These may take much longer than normal tests
const LONG_TIMEOUT = 60000;

// Used to get an ID token and id token from the AS
const issuer1TokenParams = {
  ISSUER,
  CLIENT_ID,
  USERNAME,
  PASSWORD,
  REDIRECT_URI,
  NONCE
};


describe('Jwt Verifier - Verify ID Token', () => {
  describe('ID Token basic validation', () => {
    const mockKidAsKeyFetch = (verifier) => {
      verifier.jwksClient.getSigningKey = jest.fn( ( kid, onKeyResolve ) => {
        onKeyResolve(null, { publicKey: kid } );
      });
    };

    it('fails if the signature is invalid', () => {
      const token = createToken({
        aud: '0oaoesxtxmPf08QHk0h7',
        iss: ISSUER,
      }, {
        kid: rsaKeyPair.wrongPublic,
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyIdToken(token, '0oaoesxtxmPf08QHk0h7')
        .then( () => { throw new Error('Invalid Signature was accepted'); } )
        .catch( err => {
          expect(err.message).toBe('Signature verification failed');
        });
    });

    it('passes if the signature is valid', () => {
      const token = createToken({
        aud: '0oaoesxtxmPf08QHk0h7',
        iss: ISSUER,
      }, {
        kid: rsaKeyPair.public
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyIdToken(token, '0oaoesxtxmPf08QHk0h7');
    });

    it('fails if iss claim does not match verifier issuer', () => {
      const token = createToken({
        aud: '0oaoesxtxmPf08QHk0h7',
        iss: 'not-the-issuer',
      }, {
        kid: rsaKeyPair.public // For override of key retrieval below
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyIdToken(token, '0oaoesxtxmPf08QHk0h7')
        .then( () => { throw new Error('invalid issuer did not throw an error'); } )
        .catch( err => {
          expect(err.message).toBe(`issuer not-the-issuer does not match expected issuer: ${ISSUER}`);
        });
    });

    it('fails when no audience expectation is passed', () => {
      const token = createToken({
        aud: 'any_client_id',
        iss: ISSUER,
      }, {
        kid: rsaKeyPair.public // For override of key retrieval below
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyIdToken(token)
        .then( () => { throw new Error('expected client id should be required, but was not'); } )
        .catch( err => {
          expect(err.message).toBe(`expected client id is required`);
        });
    });

    it('passes when given an audience matching expectation string', () => {
      const token = createToken({
        aud: '0oaoesxtxmPf08QHk0h7',
        iss: ISSUER,
      }, {
        kid: rsaKeyPair.public // For override of key retrieval below
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyIdToken(token, '0oaoesxtxmPf08QHk0h7');
    });

    it('fails with a invalid audience when given a valid expectation', () => {
      const token = createToken({
        aud: 'wrong_client_id',
        iss: ISSUER,
      }, {
        kid: rsaKeyPair.public // For override of key retrieval below
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyIdToken(token, '0oaoesxtxmPf08QHk0h7')
        .then( () => { throw new Error('Invalid audience claim was accepted') } )
        .catch(err => {
          expect(err.message).toBe(`audience claim wrong_client_id does not match expected client id: 0oaoesxtxmPf08QHk0h7`);
        });
    });

    it('fails with a invalid client id', () => {
      const token = createToken({
        aud: '{clientId}',
        iss: ISSUER,
      }, {
        kid: rsaKeyPair.public // For override of key retrieval below
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyIdToken(token, '{clientId}')
        .then( () => { throw new Error('Invalid client id was accepted') } )
        .catch(err => {
          expect(err.message).toBe("Replace {clientId} with the client ID of your Application. You can copy it from the Okta Developer Console in the details for the Application you created. Follow these instructions to find it: https://bit.ly/finding-okta-app-credentials");
        });
    });

    it('fails when no nonce expectation is passed', () => {
      const token = createToken({
        aud: '0oaoesxtxmPf08QHk0h7',
        iss: ISSUER,
        nonce: 'foo'
      }, {
        kid: rsaKeyPair.public // For override of key retrieval below
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyIdToken(token, '0oaoesxtxmPf08QHk0h7')
        .then( () => { throw new Error('expected nonce should be required, but was not'); } )
        .catch( err => {
          expect(err.message).toBe(`expected nonce is required`);
        });
    });

    it('fails when an nonce expectation is passed but claim is missing', () => {
      const token = createToken({
        aud: '0oaoesxtxmPf08QHk0h7',
        iss: ISSUER
      }, {
        kid: rsaKeyPair.public // For override of key retrieval below
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyIdToken(token, '0oaoesxtxmPf08QHk0h7', 'some')
        .then( () => { throw new Error('should not pass verification'); } )
        .catch( err => {
          expect(err.message).toBe(`nonce claim is missing but expected: some`);
        });
    });

    it('passes when given an nonce matching expectation string', () => {
      const token = createToken({
        aud: '0oaoesxtxmPf08QHk0h7',
        iss: ISSUER,
        nonce: 'foo'
      }, {
        kid: rsaKeyPair.public // For override of key retrieval below
      });
  
      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);
  
      return verifier.verifyIdToken(token, '0oaoesxtxmPf08QHk0h7', 'foo');
    });
  
    it('fails with an invalid nonce when given a valid expectation', () => {
      const token = createToken({
        aud: '0oaoesxtxmPf08QHk0h7',
        iss: ISSUER,
        nonce: 'foo'
      }, {
        kid: rsaKeyPair.public // For override of key retrieval below
      });
  
      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);
  
      // Not valid expectation
      return verifier.verifyIdToken(token, '0oaoesxtxmPf08QHk0h7', 'bar')
        .then( () => { throw new Error('Invalid nonce claim was accepted') } )
        .catch(err => {
          expect(err.message).toBe(`nonce claim foo does not match expected nonce: bar`);
        })
      // Expectation matches claim but in different case
      .then( () => verifier.verifyIdToken(token, '0oaoesxtxmPf08QHk0h7', 'FOO') )
        .then( () => { throw new Error('Invalid nonce claim was accepted') } )
        .catch(err => {
          expect(err.message).toBe(`nonce claim foo does not match expected nonce: FOO`);
        })
      // Value is not a string
      .then( () => verifier.verifyIdToken(token, '0oaoesxtxmPf08QHk0h7', {}) )
        .then( () => { throw new Error('Invalid nonce claim was accepted') } )
        .catch(err => {
          expect(err.message).toBe(`nonce claim foo does not match expected nonce: [object Object]`);
        })
    });
  
  });


  describe('ID Token custom claim tests with stubs', () => {
    const otherClaims = { 
      iss: ISSUER,
      aud: '0oaoesxtxmPf08QHk0h7',
    };

    const verifier = createVerifier();

    it('should only allow includes operator for custom claims', () => {
      verifier.claimsToAssert = {'groups.blarg': 'Everyone'};
      verifier.verifier = createCustomClaimsVerifier({
        groups: ['Everyone', 'Another']
      }, otherClaims);

      return verifier.verifyIdToken('anything', otherClaims.aud)
      .catch(err => expect(err.message).toBe(
        `operator: 'blarg' invalid. Supported operators: 'includes'.`
      ));
    });

    it('should succeed in asserting claims where includes is flat, claim is array', () => {
      verifier.claimsToAssert = {'groups.includes': 'Everyone'};
      verifier.verifier = createCustomClaimsVerifier({
        groups: ['Everyone', 'Another']
      }, otherClaims);

      return verifier.verifyIdToken('anything', otherClaims.aud)
      .then(jwt => expect(jwt.claims.groups).toEqual(['Everyone', 'Another']));
    });

    it('should succeed in asserting claims where includes is flat, claim is flat', () => {
      verifier.claimsToAssert = {'scp.includes': 'promos:read'};
      verifier.verifier = createCustomClaimsVerifier({
        scp: 'promos:read promos:write'
      }, otherClaims);

      return verifier.verifyIdToken('anything', otherClaims.aud)
      .then(jwt => expect(jwt.claims.scp).toBe('promos:read promos:write'));
    });

    it('should fail in asserting claims where includes is flat, claim is array', () => {
      verifier.claimsToAssert = {'groups.includes': 'Yet Another'};
      verifier.verifier = createCustomClaimsVerifier({
        groups: ['Everyone', 'Another']
      }, otherClaims);

      return verifier.verifyIdToken('anything', otherClaims.aud)
      .then( () => { throw new Error(`Invalid 'groups' claim was accepted`) } )
      .catch(err => expect(err.message).toBe(
        `claim 'groups' value 'Everyone,Another' does not include expected value 'Yet Another'`
      ));
    });

    it('should fail in asserting claims where includes is flat, claim is flat', () => {
      const expectedAud = '0oaoesxtxmPf08QHk0h7';
      verifier.claimsToAssert = {'scp.includes': 'promos:delete'};
      verifier.verifier = createCustomClaimsVerifier({
        scp: 'promos:read promos:write'
      }, otherClaims);

      return verifier.verifyIdToken('anything', otherClaims.aud)
      .then( () => { throw new Error(`Invalid 'scp' claim was accepted`) } )
      .catch(err => expect(err.message).toBe(
        `claim 'scp' value 'promos:read promos:write' does not include expected value 'promos:delete'`
      ));
    });

    it('should succeed in asserting claims where includes is array, claim is array', () => {
      verifier.claimsToAssert = {'groups.includes': ['Everyone', 'Yet Another']};
      verifier.verifier = createCustomClaimsVerifier({
        groups: ['Everyone', 'Another', 'Yet Another']
      }, otherClaims);

      return verifier.verifyIdToken('anything', otherClaims.aud)
      .then(jwt => expect(jwt.claims.groups).toEqual(['Everyone', 'Another', 'Yet Another']));
    });

    it('should succeed in asserting claims where includes is array, claim is flat', () => {
      verifier.claimsToAssert = {'scp.includes': ['promos:read', 'promos:delete']};
      verifier.verifier = createCustomClaimsVerifier({
        scp: 'promos:read promos:write promos:delete'
      }, otherClaims);

      return verifier.verifyIdToken('anything', otherClaims.aud)
      .then(jwt => expect(jwt.claims.scp).toBe('promos:read promos:write promos:delete'));
    });

    it('should fail in asserting claims where includes is array, claim is array', () => {
      verifier.claimsToAssert = {'groups.includes': ['Yet Another']};
      verifier.verifier = createCustomClaimsVerifier({
        groups: ['Everyone', 'Another']
      }, otherClaims);

      return verifier.verifyIdToken('anything', otherClaims.aud)
      .then( () => { throw new Error(`Invalid 'groups' claim was accepted`) } )
      .catch(err => expect(err.message).toBe(
        `claim 'groups' value 'Everyone,Another' does not include expected value 'Yet Another'`
      ));
    });

    it('should fail in asserting claims where includes is array, claim is flat', () => {
      verifier.claimsToAssert = {'scp.includes': ['promos:delete']};
      verifier.verifier = createCustomClaimsVerifier({
        scp: 'promos:read promos:write'
      }, otherClaims);

      return verifier.verifyIdToken('anything', otherClaims.aud)
      .then( () => { throw new Error(`Invalid 'scp' claim was accepted`) } )
      .catch(err => expect(err.message).toBe(
        `claim 'scp' value 'promos:read promos:write' does not include expected value 'promos:delete'`
      ));
    });
  });
  
});
