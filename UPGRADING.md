# Upgrading between versions of @okta/jwt-verifier

## Upgrading to the 5.x series

v5 replaces `njwt` and `jwks-rsa` with `@okta/auth-foundation` and the platform `fetch`.

### Node.js 22 or newer is required

### `requestAgent` and `requestAgentOptions` are removed

Passing either option throws a `ConfigurationValidationError`. Node `http.Agent`s are not compatible with `fetch`. Use an [undici](https://undici.nodejs.org) `Dispatcher` instead (`undici` is an optional peer dependency):

```javascript
// v4
const verifier = new OktaJwtVerifier({ issuer, requestAgent: new HttpsProxyAgent('http://proxy:8080') });

// v5
import { ProxyAgent } from 'undici';
const verifier = new OktaJwtVerifier({ issuer, dispatcher: new ProxyAgent('http://proxy:8080') });
```

To supply your own `fetch` (test doubles, logging, non-undici proxies), use `fetchImpl`. See the README for details.

### `cacheMaxAge` and `jwksRequestsPerMinute` are removed

Passing either option throws a `ConfigurationValidationError`. Keys are cached for one hour, and refreshed (at most every 30 seconds) when a `kid` is not found. There is no per-minute rate limit.

### The returned `jwt` is an `@okta/auth-foundation` `JWT`

`verifyAccessToken` and `verifyIdToken` now resolve with a `JWT` instance (also exported from this package). Changes from v4:

* `jwt.claims`, `jwt.header` and `jwt.toString()` still work.
* `jwt.isExpired()` and `jwt.isNotBefore()` (functions) are removed. Signature, `exp` and `nbf` are verified before the token is returned, so a resolved `jwt` is already unexpired. **Do not rely on the `jwt.isExpired` getter in `@okta/auth-foundation` 0.9.0**, it returns the inverted value.
* `jwt.rawValue`, `jwt.audience`, `jwt.issuer`, `jwt.subject`, `jwt.expirationTime`, etc. are new getters.
* Some error messages changed (for example missing or unknown `kid`: `No KID specified` / `No public key found`).

### `verifyIdToken` applies OIDC ID token validation

In addition to the v4 checks, ID tokens are validated with the `@okta/auth-foundation` `DefaultIDTokenValidator`: issuer, audience, HTTPS issuer, expiration, `iat` within a 5 minute grace interval, and nonce. ID tokens must not be used to authorize requests to a resource server; use `verifyAccessToken`.

### Module formats

The package ships both ESM and CommonJS (`require`) builds. TypeScript types are generated from the source.

## Upgrading to the 1.x series

### `expectedAud` is new and required 

The 0.x series `verifyAccessToken(tokenString)` is replaced by `verifyAccessToken(tokenString, expectedAud)`.

The `expectedAud` parameter is required, and must match the `aud` claim within the ticket.  

"api://default" is a common value for this claim if not set otherwise.

Additional validations are made (such as the `iss` claim must match the `issuer` given to the verifier), but they should always have been true and don't require additional configuration

### The `clientId` is no longer required

Access Tokens are not required to be bound to a clientId, so the requirement of passing a clientId to the `OktaJwtVerifier()` constructor has been removed.  You can pass the clientId and assert that any `cid` claim matches by using the "Custom Claims Assertions" as outlined in the README.
