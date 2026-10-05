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

import { jest } from '@jest/globals';
import { createFetchImplementation } from '../../src/fetch.ts';

describe('createFetchImplementation', () => {
  const dispatcher: any = { name: 'fake-dispatcher' };

  it('uses global fetch by default', async () => {
    const spy = jest.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{}'));
    await createFetchImplementation()('https://foo/keys', { method: 'GET' });
    expect(spy).toHaveBeenCalledWith('https://foo/keys', { method: 'GET' });
  });

  it('uses fetchImpl when provided', async () => {
    const fetchImpl = jest.fn<typeof fetch>().mockResolvedValue(new Response('{}'));
    await createFetchImplementation({ fetchImpl })('https://foo/keys');
    expect(fetchImpl).toHaveBeenCalledWith('https://foo/keys');
  });

  it('passes dispatcher to global fetch', async () => {
    const spy = jest.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{}'));
    await createFetchImplementation({ dispatcher })('https://foo/keys', { method: 'GET' });
    expect(spy).toHaveBeenCalledWith('https://foo/keys', { method: 'GET', dispatcher });
  });

  it('passes dispatcher to fetchImpl when both are set', async () => {
    const fetchImpl = jest.fn<typeof fetch>().mockResolvedValue(new Response('{}'));
    await createFetchImplementation({ fetchImpl, dispatcher })('https://foo/keys', { method: 'GET' });
    expect(fetchImpl).toHaveBeenCalledWith('https://foo/keys', { method: 'GET', dispatcher });
  });
});
