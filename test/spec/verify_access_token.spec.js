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


const constants = require('../constants');

const { createToken, createVerifier, createCustomClaimsVerifier, rsaKeyPair } = require('../util');

// These need to be exported in the environment, from a working Okta org
const ISSUER = constants.ISSUER;

describe('Jwt Verifier - Verify Access Token', () => {

  describe('Access Token basic validation', () => {
    const mockKidAsKeyFetch = (verifier) => {
      verifier.jwksClient.getSigningKey = jest.fn( ( kid, onKeyResolve ) => {
        onKeyResolve(null, { publicKey: kid } );
      });
    };

    it('fails if the signature is invalid', () => {
      const token = createToken({
        aud: 'http://myapp.com/',
        iss: ISSUER,
      }, {
        kid: rsaKeyPair.wrongPublic,
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyAccessToken(token, 'http://myapp.com/')
        .then( () => { throw new Error('Invalid Signature was accepted'); } )
        .catch( err => {
          expect(err.message).toBe('Signature verification failed');
        });
    });

    it('passes if the signature is valid', () => {
      const token = createToken({
        aud: 'http://myapp.com/',
        iss: ISSUER,
      }, {
        kid: rsaKeyPair.public
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyAccessToken(token, 'http://myapp.com/');
    });

    it('fails if iss claim does not match verifier issuer', () => {
      const token = createToken({
        aud: 'http://myapp.com/',
        iss: 'not-the-issuer',
      }, {
        kid: rsaKeyPair.public // For override of key retrieval below
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyAccessToken(token, 'http://myapp.com/')
        .then( () => { throw new Error('invalid issuer did not throw an error'); } )
        .catch( err => {
          expect(err.message).toBe(`issuer not-the-issuer does not match expected issuer: ${ISSUER}`);
        });
    });

    it('fails when no audience expectation is passed', () => {
      const token = createToken({
        aud: 'http://any-aud.com/',
        iss: ISSUER,
      }, {
        kid: rsaKeyPair.public // For override of key retrieval below
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyAccessToken(token)
        .then( () => { throw new Error('expected audience should be required, but was not'); } )
        .catch( err => {
          expect(err.message).toBe(`expected audience is required`);
        });
    });

    it('passes when given an audience matching expectation string', () => {
      const token = createToken({
        aud: 'http://myapp.com/',
        iss: ISSUER,
      }, {
        kid: rsaKeyPair.public // For override of key retrieval below
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyAccessToken(token, 'http://myapp.com/');
    });

    it('passes when given an audience matching expectation array', () => {
      const token = createToken({
        aud: 'http://myapp.com/',
        iss: ISSUER,
      }, {
        kid: rsaKeyPair.public // For override of key retrieval below
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyAccessToken(token, [ 'one', 'http://myapp.com/', 'three'] );
    });
    
    it('passes when given an audience that is an array and matches the expectation', () => {
      const token = createToken({
        aud: ['http://myapp.com/', 'one'],
        iss: ISSUER,
      }, {
        kid: rsaKeyPair.public // For override of key retrieval below
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyAccessToken(token, 'http://myapp.com/');
    })

    it('passes when given an audience that is an array and there is a match in the expectation array', () => {
      const token = createToken({
        aud: ['http://myapp.com/', 'one'],
        iss: ISSUER,
      }, {
        kid: rsaKeyPair.public // For override of key retrieval below
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyAccessToken(token, ['two', 'http://myapp.com/']);
    })

    it('fails when given an audience that is an array and doesnt match the expectation', () => {
      const token = createToken({
        aud: ['http://myapp.com/', 'one'],
        iss: ISSUER,
      }, {
        kid: rsaKeyPair.public // For override of key retrieval below
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyAccessToken(token, 'two');
    })

    it('fails when given an audience that is an array and there is no match in the expectation array', () => {
      const token = createToken({
        aud: ['http://myapp.com/', 'one'],
        iss: ISSUER,
      }, {
        kid: rsaKeyPair.public // For override of key retrieval below
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyAccessToken(token, ['two', 'three']);
    })
    
    it('fails with a invalid audience when given a valid expectation', () => {
      const token = createToken({
        aud: 'http://wrong-aud.com/',
        iss: ISSUER,
      }, {
        kid: rsaKeyPair.public // For override of key retrieval below
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyAccessToken(token, 'http://myapp.com/')
        .then( () => { throw new Error('Invalid audience claim was accepted') } )
        .catch(err => {
          expect(err.message).toBe(`audience claim http://wrong-aud.com/ does not match expected audience: http://myapp.com/`);
        });
    });

    it('fails with a invalid audience when given an array of expectations', () => {
      const token = createToken({
        aud: 'http://wrong-aud.com/',
        iss: ISSUER,
      }, {
        kid: rsaKeyPair.public // For override of key retrieval below
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyAccessToken(token, ['one', 'http://myapp.com/', 'three'])
        .then( () => { throw new Error('Invalid audience claim was accepted') } )
        .catch(err => {
          expect(err.message).toBe(`audience claim http://wrong-aud.com/ does not match one of the expected audiences: one, http://myapp.com/, three`);
        });
    });

    it('fails when given an empty array of audience expectations', () => {
      const token = createToken({
        aud: 'http://any-aud.com/',
        iss: ISSUER,
      }, {
        kid: rsaKeyPair.public // For override of key retrieval below
      });

      const verifier = createVerifier();
      mockKidAsKeyFetch(verifier);

      return verifier.verifyAccessToken(token, [])
        .then( () => { throw new Error('Invalid audience claim was accepted') } )
        .catch(err => {
          expect(err.message).toBe(`audience claim http://any-aud.com/ does not match one of the expected audiences: `);
        });
    });
  });


  describe('Access Token custom claim tests with stubs', () => {
    const otherClaims = { 
      iss: ISSUER,
      aud: 'http://myapp.com/',
    };

    const verifier = createVerifier();

    it('should only allow includes operator for custom claims', () => {
      verifier.claimsToAssert = {'groups.blarg': 'Everyone'};
      verifier.verifier = createCustomClaimsVerifier({
        groups: ['Everyone', 'Another']
      }, otherClaims);

      return verifier.verifyAccessToken('anything', otherClaims.aud)
      .catch(err => expect(err.message).toBe(
        `operator: 'blarg' invalid. Supported operators: 'includes'.`
      ));
    });

    it('should succeed in asserting claims where includes is flat, claim is array', () => {
      verifier.claimsToAssert = {'groups.includes': 'Everyone'};
      verifier.verifier = createCustomClaimsVerifier({
        groups: ['Everyone', 'Another']
      }, otherClaims);

      return verifier.verifyAccessToken('anything', otherClaims.aud)
      .then(jwt => expect(jwt.claims.groups).toEqual(['Everyone', 'Another']));
    });

    it('should succeed in asserting claims where includes is flat, claim is flat', () => {
      verifier.claimsToAssert = {'scp.includes': 'promos:read'};
      verifier.verifier = createCustomClaimsVerifier({
        scp: 'promos:read promos:write'
      }, otherClaims);

      return verifier.verifyAccessToken('anything', otherClaims.aud)
      .then(jwt => expect(jwt.claims.scp).toBe('promos:read promos:write'));
    });

    it('should fail in asserting claims where includes is flat, claim is array', () => {
      verifier.claimsToAssert = {'groups.includes': 'Yet Another'};
      verifier.verifier = createCustomClaimsVerifier({
        groups: ['Everyone', 'Another']
      }, otherClaims);

      return verifier.verifyAccessToken('anything', otherClaims.aud)
      .then( () => { throw new Error(`Invalid 'groups' claim was accepted`) } )
      .catch(err => expect(err.message).toBe(
        `claim 'groups' value 'Everyone,Another' does not include expected value 'Yet Another'`
      ));
    });

    it('should fail in asserting claims where includes is flat, claim is flat', () => {
      const expectedAud = 'http://myapp.com/';
      verifier.claimsToAssert = {'scp.includes': 'promos:delete'};
      verifier.verifier = createCustomClaimsVerifier({
        scp: 'promos:read promos:write'
      }, otherClaims);

      return verifier.verifyAccessToken('anything', otherClaims.aud)
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

      return verifier.verifyAccessToken('anything', otherClaims.aud)
      .then(jwt => expect(jwt.claims.groups).toEqual(['Everyone', 'Another', 'Yet Another']));
    });

    it('should succeed in asserting claims where includes is array, claim is flat', () => {
      verifier.claimsToAssert = {'scp.includes': ['promos:read', 'promos:delete']};
      verifier.verifier = createCustomClaimsVerifier({
        scp: 'promos:read promos:write promos:delete'
      }, otherClaims);

      return verifier.verifyAccessToken('anything', otherClaims.aud)
      .then(jwt => expect(jwt.claims.scp).toBe('promos:read promos:write promos:delete'));
    });

    it('should fail in asserting claims where includes is array, claim is array', () => {
      verifier.claimsToAssert = {'groups.includes': ['Yet Another']};
      verifier.verifier = createCustomClaimsVerifier({
        groups: ['Everyone', 'Another']
      }, otherClaims);

      return verifier.verifyAccessToken('anything', otherClaims.aud)
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

      return verifier.verifyAccessToken('anything', otherClaims.aud)
      .then( () => { throw new Error(`Invalid 'scp' claim was accepted`) } )
      .catch(err => expect(err.message).toBe(
        `claim 'scp' value 'promos:read promos:write' does not include expected value 'promos:delete'`
      ));
    });
  });
});
