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

const OktaJwtVerifier = require('../../lib');

describe('jwt-verifier configuration validation', () => {
  it('should throw if no issuer is provided', () => {
    function createInstance() {
      new OktaJwtVerifier();
    }
    expect(createInstance).toThrow();
  });

  it('should throw if an issuer that does not contain https is provided', () => {
    function createInstance() {
      new OktaJwtVerifier({
        issuer: 'http://foo.com'
      });
    }
    expect(createInstance).toThrow();
  });

  it('should not throw if https issuer validation is skipped', () => {
    jest.spyOn(console, 'warn').mockImplementation(()=>{});   // mockImplementation to stop console.warn from actually logging
    function createInstance() {
      new OktaJwtVerifier({
        issuer: 'http://foo.com',
        testing: {
          disableHttpsCheck: true
        }
      });
    }
    expect(createInstance).not.toThrow();
    expect(console.warn).toBeCalledWith('Warning: HTTPS check is disabled. This allows for insecure configurations and is NOT recommended for production use.');
  });

  it('should throw if an issuer matching {yourOktaDomain} is provided', () => {
    function createInstance() {
      new OktaJwtVerifier({
        issuer: 'https://{yourOktaDomain}'
      });
    }
    expect(createInstance).toThrow();
  });

  it('should throw if an issuer matching -admin.okta.com is provided', () => {
    function createInstance() {
      new OktaJwtVerifier({
        issuer: 'https://foo-admin.okta.com'
      });
    }
    expect(createInstance).toThrow();
  });

  it('should throw if an issuer matching -admin.oktapreview.com is provided', () => {
    function createInstance() {
      new OktaJwtVerifier({
        issuer: 'https://foo-admin.oktapreview.com'
      });
    }
    expect(createInstance).toThrow();
  });

  it('should throw if an issuer matching -admin.okta-emea.com is provided', () => {
    function createInstance() {
      new OktaJwtVerifier({
        issuer: 'https://foo-admin.okta-emea.com'
      });
    }
    expect(createInstance).toThrow();
  });

  it('should throw if clientId matching {clientId} is provided', () => {
    function createInstance() {
      new OktaJwtVerifier({
        issuer: 'https://foo',
        clientId: '{clientId}',
      });
    }
    expect(createInstance).toThrow();
  });

  it('should throw if `requestAgentOptions` is passed', () => {
    function createInstance() {
      new OktaJwtVerifier({
        issuer: 'https://foo',
        clientId: '123456',
        requestAgentOptions: {
          timeout: 10000
        }
      });
    }

    expect(createInstance).toThrow();
  });

  it('should NOT throw if clientId not matching {clientId} is provided', () => {
    function createInstance() {
      new OktaJwtVerifier({
        issuer: 'https://foo',
        clientId: '123456',
      });
    }
    expect(createInstance).not.toThrow();
  });

  it('should return issuer-based jwks uri when custom jwksUri is not specified', () => {

    const verifier = new OktaJwtVerifier({
      issuer: 'https://foo',
      clientId: '123456',
    });

    expect(verifier.jwksUri).toEqual('https://foo/v1/keys');
  });

  [undefined, ''].forEach(jwksUri =>
    it(`should return issuer-based jwks uri when jwks custom uri is ${jwksUri}`, () => {

      const verifier = new OktaJwtVerifier({
        issuer: 'https://foo',
        clientId: '123456',
        jwksUri: jwksUri
      });

      expect(verifier.jwksUri).toEqual('https://foo/v1/keys');
    })
  );

  it('should return custom jwks uri when specified', () => {

    const customJwksUri = 'http://custom-jwks-uri/keys';

    const verifier = new OktaJwtVerifier({
      issuer: 'https://foo',
      clientId: '123456',
      jwksUri: customJwksUri
    });

    expect(verifier.jwksUri).toEqual(customJwksUri);
  });

  it('should configure getKeysInterceptor', () => {
    new OktaJwtVerifier({
      issuer: 'https://foo',
      clientId: '123456',
      getKeysInterceptor: () => []
    });

    new OktaJwtVerifier({
      issuer: 'https://foo',
      clientId: '123456',
      getKeysInterceptor: async () => []
    });
  });

});
