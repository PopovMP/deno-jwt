# JWT

A module for working with JSON Web Tokens (JWT).

```typescript
import { createJwt, getJwtPayload, isJwtExpired, isJwtValid } from "@popov/jst";

const nowSec = Math.floor(Date.now() / 1000);
const oneHour = 60 * 60;

const payload = {
  "iss": "Deno Land",
  "iat": nowSec,
  "exp": nowSec + oneHour,
  "aud": "deno.com",
};

// Create JWT with a key
const key = "foobar";
const jwt = await createJwt(payload, key);

// Check is the JWT valid
const isValid = await isJwtValid(jwt, key);

// Check is the JWT has expired
const isExpired = isJwtExpired(jwt);

// Gets the JWT payload
const payload = getJwtPayload(jwt);
```
