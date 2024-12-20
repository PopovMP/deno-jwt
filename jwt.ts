import {
  base64ToBase64Url,
  base64ToString,
  base64UrlToBase64,
  bytesToBase64,
  stringToBase64,
} from "@popov/base64";

/**
 * Creates a JWT
 *
 * ```typescript
 * function createJwt(payload: object, key: string): Promise<string>
 * ```
 */
export async function createJwt(payload: object, key: string): Promise<string> {
  const headerText = JSON.stringify({ typ: "JWT", alg: "HS256" });
  const payloadText = JSON.stringify(payload);
  const base64Header = stringToBase64(headerText);
  const base64Payload = stringToBase64(payloadText);
  const urlHeader = base64ToBase64Url(base64Header);
  const urlPayload = base64ToBase64Url(base64Payload);
  const signature = await encodeSha256(`${urlHeader}.${urlPayload}`, key);

  return `${urlHeader}.${urlPayload}.${signature}`;
}

/**
 * Validates a JWT
 *
 * This function checks if the JWT is valid and not expired
 *
 * ```typescript
 * function isJwtValid(jwt: string, key: string): Promise<boolean>
 * ```
 */
export async function isJwtValid(jwt: string, key: string): Promise<boolean> {
  // Get the three parts of the JWT
  const parts = jwt.split(".");
  if (parts.length !== 3) return false;

  // Validate JWT signature
  const [header, payload, signature] = parts;
  if (header === "" || payload === "" || signature === "") return false;

  const actualSignature = await encodeSha256(`${header}.${payload}`, key);
  if (actualSignature !== signature) return false;

  // Check if the JWT is expired
  return !isJwtExpired(jwt);
}

/**
 * Checks if the JWT has expired
 *
 * ```typescript
 * function isJwtExpired(jwt: string): boolean
 * ```
 */
export function isJwtExpired(jwt: string): boolean {
  const payload = getJwtPayload(jwt) as { exp: number };
  if (!payload.exp) return false;

  return Math.floor(Date.now() / 1000) > payload.exp;
}

/**
 * Gets the payload from a JWT
 *
 * ```typescript
 * function getJwtPayload(jwt: string): object
 * ```
 */
export function getJwtPayload(jwt: string): object {
  const parts = jwt.split(".");
  if (parts.length !== 3) return {};

  const payloadBase64Url = parts[1];
  const payloadBase64 = base64UrlToBase64(payloadBase64Url);
  const payloadText = base64ToString(payloadBase64);
  return JSON.parse(payloadText);
}

/**
 * Encodes the data using HMAC SHA-256 and makes it URL valid
 */
async function encodeSha256(data: string, key: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBytes = encoder.encode(data);
  const keyBytes = encoder.encode(key);
  const algorithm = { name: "HMAC", hash: { name: "SHA-256" } };

  const cryptoKey: CryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    algorithm,
    false,
    ["sign"],
  );

  const signedBuff: ArrayBuffer = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    dataBytes,
  );

  const base64 = bytesToBase64(new Uint8Array(signedBuff));

  return base64ToBase64Url(base64);
}
