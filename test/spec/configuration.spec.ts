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

import OktaJwtVerifier, { ConfigurationValidationError } from '../../src/index.ts';
import { jest } from '@jest/globals';

const create = (options: any = {}) => () => new OktaJwtVerifier(options);

describe('jwt-verifier configuration validation', () => {
  it('should throw if no issuer is provided', () => {
    expect(create(undefined)).toThrow(ConfigurationValidationError);
  });

  it('should throw if an issuer that does not contain https is provided', () => {
    expect(create({ issuer: 'http://foo.com' })).toThrow();
  });

  it('should not throw if https issuer validation is skipped', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
    expect(create({ issuer: 'http://foo.com', testing: { disableHttpsCheck: true } })).not.toThrow();
    expect(warn).toHaveBeenCalledWith(
      'Warning: HTTPS check is disabled. This allows for insecure configurations and is NOT recommended for production use.'
    );
  });

  it.each([
    'https://{yourOktaDomain}',
    'https://foo-admin.okta.com',
    'https://foo-admin.oktapreview.com',
    'https://foo-admin.okta-emea.com',
  ])('should throw if issuer is %s', (issuer) => {
    expect(create({ issuer })).toThrow();
  });

  it('should throw if clientId matching {clientId} is provided', () => {
    expect(create({ issuer: 'https://foo', clientId: '{clientId}' })).toThrow();
  });

  it('should NOT throw if clientId not matching {clientId} is provided', () => {
    expect(create({ issuer: 'https://foo', clientId: '123456' })).not.toThrow();
  });

  describe('removed v4 options', () => {
    it.each(['requestAgent', 'requestAgentOptions', 'cacheMaxAge', 'jwksRequestsPerMinute'])(
      'should throw a migration error if `%s` is passed', (name) => {
        expect(create({ issuer: 'https://foo', [name]: {} }))
          .toThrow(new RegExp(`\\\`${name}\\\` option was removed in v5`));
      }
    );

    it('points requestAgent users to dispatcher', () => {
      expect(create({ issuer: 'https://foo', requestAgent: {} })).toThrow(/dispatcher/);
    });
  });

  describe('jwksUri', () => {
    it('should return issuer-based jwks uri when custom jwksUri is not specified', () => {
      expect(new OktaJwtVerifier({ issuer: 'https://foo' }).jwksUri).toEqual('https://foo/v1/keys');
    });

    it.each([undefined, ''])('should return issuer-based jwks uri when jwksUri is %p', (jwksUri) => {
      expect(new OktaJwtVerifier({ issuer: 'https://foo', jwksUri }).jwksUri).toEqual('https://foo/v1/keys');
    });

    it('should return custom jwks uri when specified', () => {
      const jwksUri = 'http://custom-jwks-uri/keys';
      expect(new OktaJwtVerifier({ issuer: 'https://foo', jwksUri }).jwksUri).toEqual(jwksUri);
    });
  });

  it('should accept getKeysInterceptor', () => {
    expect(create({ issuer: 'https://foo', getKeysInterceptor: async () => [] })).not.toThrow();
  });
});
