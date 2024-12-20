/**
 * # JWT
 *
 * A module for working with JSON Web Tokens (JWT).
 *
 * ```typescript
 * import { createJwt, isJwtValid, isJwtExpired, getJwtPayload } from "@popov/jst";
 *
 * const nowSec = Math.floor(Date.now() / 1000);
 * const oneHour = 60 * 60;
 *
 * const payload = {
 *   "iss": "Deno Land",
 *   "iat": nowSec,
 *   "exp": nowSec + oneHour,
 *   "aud": "deno.com",
 * };
 *
 * const key = "foobar";
 * const jwt = await createJwt(payload, key);
 *
 * const isValid = await isJwtValid(jwt, key);
 * const isExpired = isJwtExpired(jwt);
 * const payload = getJwtPayload(jwt);
 * ```
 *
 * @module mod.ts
 */

export * from "./jwt.ts";
