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

import { ConfigurationValidationError } from './errors.ts';

export type Claims = Record<string, unknown>;
export type ExpectedAudience = string | string[];

const findAppCredentialsURL = 'https://bit.ly/finding-okta-app-credentials';

export const assertClientId = (clientId?: string): void => {
  const copyCredentialsMessage = 'You can copy it from the Okta Developer Console ' +
    'in the details for the Application you created. ' +
    `Follow these instructions to find it: ${findAppCredentialsURL}`;

  if (!clientId) {
    throw new ConfigurationValidationError('Your client ID is missing. ' + copyCredentialsMessage);
  } else if (clientId.match(/{clientId}/)) {
    throw new ConfigurationValidationError(
      'Replace {clientId} with the client ID of your Application. ' + copyCredentialsMessage);
  }
};

class AssertedClaimsVerifier {
  errors: string[] = [];

  extractOperator (claim: string): string | undefined {
    const idx = claim.indexOf('.');
    return idx >= 0 ? claim.substring(idx + 1) : undefined;
  }

  extractClaim (claim: string): string {
    const idx = claim.indexOf('.');
    return idx >= 0 ? claim.substring(0, idx) : claim;
  }

  isValidOperator (operator?: string): boolean {
    // may support more operators in the future
    return !operator || operator === 'includes';
  }

  checkAssertions (op: string | undefined, claim: string, expectedValue: any, actualValue: any): void {
    if (!op && actualValue !== expectedValue) {
      this.errors.push(`claim '${claim}' value '${actualValue}' does not match expected value '${expectedValue}'`);
    } else if (op === 'includes' && Array.isArray(expectedValue)) {
      expectedValue.forEach((value) => {
        if (!actualValue || !actualValue.includes(value)) {
          this.errors.push(`claim '${claim}' value '${actualValue}' does not include expected value '${value}'`);
        }
      });
    } else if (op === 'includes' && (!actualValue || !actualValue.includes(expectedValue))) {
      this.errors.push(`claim '${claim}' value '${actualValue}' does not include expected value '${expectedValue}'`);
    }
  }
}

export function verifyAssertedClaims (claimsToAssert: Claims, claims: Claims): void {
  const assertedClaimsVerifier = new AssertedClaimsVerifier();
  for (const [claimName, expectedValue] of Object.entries(claimsToAssert)) {
    const operator = assertedClaimsVerifier.extractOperator(claimName);
    if (!assertedClaimsVerifier.isValidOperator(operator)) {
      throw new Error(`operator: '${operator}' invalid. Supported operators: 'includes'.`);
    }
    const claim = assertedClaimsVerifier.extractClaim(claimName);
    assertedClaimsVerifier.checkAssertions(operator, claim, expectedValue, claims[claim]);
  }
  if (assertedClaimsVerifier.errors.length) {
    throw new Error(assertedClaimsVerifier.errors.join(', '));
  }
}

export function verifyAudience (expected: ExpectedAudience | undefined, aud: unknown): void {
  if (!expected) {
    throw new Error('expected audience is required');
  }

  if (!Array.isArray(aud)) {
    if (Array.isArray(expected) && !expected.includes(aud as string)) {
      throw new Error(`audience claim ${aud} does not match one of the expected audiences: ${expected.join(', ')}`);
    }

    if (!Array.isArray(expected) && aud !== expected) {
      throw new Error(`audience claim ${aud} does not match expected audience: ${expected}`);
    }
  } else {
    if (Array.isArray(expected) && !(aud.some(val => expected.includes(val)))) {
      throw new Error(`audience claims ${aud.join(', ')} do not match one of the expected audiences: ${expected}`);
    }

    if (!Array.isArray(expected) && !aud.includes(expected)) {
      throw new Error(`audience claims ${aud.join(', ')} do not include expected audience: ${expected}`);
    }
  }
}

export function verifyIssuer (expected: string, issuer: unknown): void {
  if (issuer !== expected) {
    throw new Error(`issuer ${issuer} does not match expected issuer: ${expected}`);
  }
}

export function verifyClientId (expected: string | undefined, aud: unknown): void {
  if (!expected) {
    throw new Error('expected client id is required');
  }

  assertClientId(expected);

  if (aud !== expected) {
    throw new Error(`audience claim ${aud} does not match expected client id: ${expected}`);
  }
}

export function verifyNonce (expected: string | undefined, nonce: unknown): void {
  if (nonce && !expected) {
    throw new Error('expected nonce is required');
  }
  if (!nonce && expected) {
    throw new Error(`nonce claim is missing but expected: ${expected}`);
  }
  if (nonce && expected && nonce !== expected) {
    throw new Error(`nonce claim ${nonce} does not match expected nonce: ${expected}`);
  }
}
