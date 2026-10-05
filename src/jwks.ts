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

import { isJWKS, type JWKS } from '@okta/auth-foundation';

export const DEFAULT_CACHE_TTL = 60 * 60 * 1000;
// minimum time between forced (cache-bypassing) refetches, prevents random `kid`s from causing a fetch per request
export const REFRESH_COOLDOWN = 30 * 1000;

export interface JwksLoaderOptions {
  jwksUri: string;
  fetchImpl: typeof fetch;
  getKeysInterceptor?: () => Promise<unknown[]>;
  cacheTtl?: number;
  refreshCooldown?: number;
}

export class JwksLoader {
  #options: JwksLoaderOptions;
  #keys: JWKS | null = null;
  #fetchedAt = 0;
  #inflight: Promise<JWKS> | null = null;

  constructor (options: JwksLoaderOptions) {
    this.#options = options;
  }

  get jwksUri (): string {
    return this.#options.jwksUri;
  }

  /** Returns cached keys, fetching if missing or expired */
  async getKeys (): Promise<JWKS> {
    const ttl = this.#options.cacheTtl ?? DEFAULT_CACHE_TTL;
    if (this.#keys && Date.now() - this.#fetchedAt < ttl) {
      return this.#keys;
    }
    return this.#load();
  }

  /**
   * Re-fetches keys bypassing the cache (used when a `kid` is not found).
   * Returns the current keys without fetching if a refresh happened within the cooldown.
   */
  async refresh (): Promise<JWKS> {
    const cooldown = this.#options.refreshCooldown ?? REFRESH_COOLDOWN;
    if (this.#keys && Date.now() - this.#fetchedAt < cooldown) {
      return this.#keys;
    }
    return this.#load();
  }

  #load (): Promise<JWKS> {
    // coalesce concurrent requests
    this.#inflight ??= this.#fetchKeys().finally(() => {
      this.#inflight = null;
    });
    return this.#inflight;
  }

  async #fetchKeys (): Promise<JWKS> {
    const { jwksUri, fetchImpl, getKeysInterceptor } = this.#options;
    let keys: unknown = getKeysInterceptor ? await getKeysInterceptor() : undefined;
    // like v4 (jwks-rsa), an interceptor that returns no keys falls back to fetching the JWKS document
    if (!Array.isArray(keys) || keys.length === 0) {
      const response = await fetchImpl(jwksUri, {
        headers: { Accept: 'application/json' },
        redirect: 'manual',
        signal: AbortSignal.timeout(30 * 1000)
      });
      if (!response.ok) {
        throw new Error(`Unable to fetch JWKS from ${jwksUri}: HTTP ${response.status}`);
      }
      keys = (await response.json() as { keys?: unknown }).keys;
    }
    if (!isJWKS(keys)) {
      throw new Error(`Unexpected JWKS response from ${jwksUri}`);
    }
    this.#keys = keys;
    this.#fetchedAt = Date.now();
    return keys;
  }
}
