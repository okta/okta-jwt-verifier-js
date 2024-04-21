import OktaJwtVerifier from '../../';
import {expect, test} from 'tstyche';

const verifier = new OktaJwtVerifier({ issuer: 'https://foo' });

const jwt = await verifier.verifyAccessToken('accessTokenString', [
  'expectedAudience',
  'expectedAudience2',
]);

test("OktaJwtVerifier constructor", () => {
  // issuer is required
  expect(verifier).type.toEqual<OktaJwtVerifier>();
  // Expected error: Missing issuer
  expect(new OktaJwtVerifier({ clientId: '1234' })).type.toRaiseError();
  // With all options
  expect(new OktaJwtVerifier({
    issuer: 'https://foo',
    clientId: '1234',
    assertClaims: { cid: '{clientId}' },
    cacheMaxAge: 1000*60*60*2,
    jwksRequestsPerMinute: 100
  })).type.toEqual<OktaJwtVerifier>();
});

test("verifyAccessToken", async () => {
  // Expected error: Missing expectedAudience
  expect(await verifier.verifyAccessToken('accessTokenString')).type.toRaiseError();
  expect(await verifier.verifyAccessToken('accessTokenString', 'expectedAudience')).type.toEqual<OktaJwtVerifier.Jwt>();
});

test("JWT", () => {
  expect(jwt.claims).type.toEqual<OktaJwtVerifier.JwtClaims>();
  expect(jwt.header).type.toEqual<OktaJwtVerifier.JwtHeader>();
  expect(jwt.toString()).type.toBeString();
});

test("JWT Claims", () => {
  expect<OktaJwtVerifier.JwtClaims>().type.toBeAssignable({    
    jti: "AT.0mP4JKAZX1iACIT4vbEDF7LpvDVjxypPMf0D7uX39RE",
    iss: "https://${yourOktaDomain}/oauth2/0oacqf8qaJw56czJi0g4",
    aud: "https://api.example.com",
    sub: "00ujmkLgagxeRrAg20g3",
    iat: 1467145094,
    exp: 1467148694,
    cid: "nmdP1fcyvdVO11AL7ECm",
    uid: "00ujmkLgagxeRrAg20g3",
    scp: [
      "openid",
      "email",
      "flights",
      "custom"
    ],
    custom_claim: "CustomValue"
  });
  expect<OktaJwtVerifier.JwtClaims>().type.not.toBeAssignable({
    exp: 'not-a-number'
  });
});

test("JWT Header", () => {
  expect<OktaJwtVerifier.JwtHeader>().type.toBeAssignable({
    alg: 'RS256' as const,
    kid: "45js03w0djwedsw",
    typ: 'JWT'
  });
  expect<OktaJwtVerifier.JwtHeader>().type.not.toBeAssignable({
    alg: 'unsupported-alg' as const,
    typ: 'JWT'
  });
});

test("verifyIdToken", async () => {
  // Expected error: Missing expectedClientId
  expect(await verifier.verifyIdToken('idTokenString')).type.toRaiseError();
  // expectedNonce is optional
  expect(await verifier.verifyIdToken('idTokenString', 'expectedClientId')).type.toEqual<OktaJwtVerifier.Jwt>();
  // Expected error: Invalid type for expectedClientId
  expect(await verifier.verifyIdToken('idTokenString', ['expectedClientId'], 'expectedNonce')).type.toRaiseError();
  expect(await verifier.verifyIdToken('idTokenString', 'expectedClientId', 'expectedNonce')).type.toEqual<OktaJwtVerifier.Jwt>();
});
