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

import type { Dispatcher } from 'undici';
import { ConfigurationValidationError } from './errors.ts';

const findDomainURL = 'https://bit.ly/finding-okta-domain';

export interface VerifierOptions {
  issuer: string;
  clientId?: string;
  assertClaims?: Record<string, unknown>;
  jwksUri?: string;
  /** Custom `fetch` implementation used for JWKS requests. Defaults to global `fetch`. */
  fetchImpl?: typeof fetch;
  /** `undici` Dispatcher (proxy, custom TLS, pooling). Passed to fetch as `{ dispatcher }`. */
  dispatcher?: Dispatcher;
  /** Overrides fetching of the JWKS document, e.g. to load keys from a local file. */
  getKeysInterceptor?: () => Promise<unknown[]>;
  testing?: {
    disableHttpsCheck?: boolean;
  };
}

export const assertIssuer = (issuer: string | undefined, testing: VerifierOptions['testing'] = {}): void => {
  const isHttps = new RegExp('^https://');
  const hasDomainAdmin = /-admin.(okta|oktapreview|okta-emea).com/;
  const copyMessage = 'You can copy your domain from the Okta Developer ' +
    'Console. Follow these instructions to find it: ' + findDomainURL;

  if (testing.disableHttpsCheck) {
    const httpsWarning = 'Warning: HTTPS check is disabled. ' +
      'This allows for insecure configurations and is NOT recommended for production use.';
    /* eslint-disable-next-line no-console */
    console.warn(httpsWarning);
  }

  if (!issuer) {
    throw new ConfigurationValidationError('Your Okta URL is missing. ' + copyMessage);
  } else if (!testing.disableHttpsCheck && !issuer.match(isHttps)) {
    throw new ConfigurationValidationError(
      'Your Okta URL must start with https. ' +
      `Current value: ${issuer}. ${copyMessage}`
    );
  } else if (issuer.match(/{yourOktaDomain}/)) {
    throw new ConfigurationValidationError('Replace {yourOktaDomain} with your Okta domain. ' + copyMessage);
  } else if (issuer.match(hasDomainAdmin)) {
    throw new ConfigurationValidationError(
      'Your Okta domain should not contain -admin. ' +
      `Current value: ${issuer}. ${copyMessage}`
    );
  }
};

const REMOVED_OPTIONS: Record<string, string> = {
  requestAgent: 'use `dispatcher` (an undici Dispatcher, e.g. ProxyAgent) or `fetchImpl` instead',
  requestAgentOptions: 'use `dispatcher` (an undici Dispatcher, e.g. ProxyAgent) or `fetchImpl` instead',
  cacheMaxAge: 'JWKS caching is now handled internally and is not configurable',
  jwksRequestsPerMinute: 'JWKS rate limiting has been removed',
};

/** Throws a migration error for v4 options that no longer exist. */
export const assertNoRemovedOptions = (options: object): void => {
  for (const [name, hint] of Object.entries(REMOVED_OPTIONS)) {
    if ((options as Record<string, unknown>)[name] !== undefined) {
      throw new ConfigurationValidationError(
        `The \`${name}\` option was removed in v5: ${hint}. See UPGRADING.md.`
      );
    }
  }
};
