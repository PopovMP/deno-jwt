import { createJwt, getJwtPayload, isJwtExpired, isJwtValid } from "./jwt.ts";

function assertEquals(actual: string, expected: string, msg?: string): void {
  if (actual !== expected) {
    throw new Error(msg || `Expected "${expected}", got "${actual}"`);
  }
}

function isOk(value: boolean, msg?: string): void {
  if (!value) {
    throw new Error(msg || `Expected true, got ${value}`);
  }
}

Deno.test("createJwt()", async () => {
  const payload = {
    "sub": "1234567890",
    "name": "John Doe",
    "iat": 1516239022,
  };
  const key = "qwertyuiopasdfghjklzxcvbnm123456";
  const actual = await createJwt(payload, key);
  const expected = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
    "qm9F4njElMyEvCFcXqH5MwGowpoDjRt91mIWyOUr-7s";
  assertEquals(actual, expected);
});

Deno.test("createJwt() 2", async () => {
  const payload = {
    "iss": "Online JWT Builder",
    "iat": 1725540872,
    "exp": 1757076872,
    "aud": "www.example.com",
    "sub": "jrocket@example.com",
    "GivenName": "Johnny",
    "Surname": "Rocket",
    "Email": "jrocket@example.com",
    "Role": [
      "Manager",
      "Project Administrator",
    ],
  };
  const key = "qwertyuiopasdfghjklzxcvbnm123456";
  const actual = await createJwt(payload, key);
  const expected = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
    "eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3MjU1NDA" +
    "4NzIsImV4cCI6MTc1NzA3Njg3MiwiYXVkIjoid3d3LmV4YW1wbGUuY2" +
    "9tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZ" +
    "SI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impy" +
    "b2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9" +
    "qZWN0IEFkbWluaXN0cmF0b3IiXX0." +
    "E9fgo0_bRYyz-yb6m5QWTtY81Lt4KcPOZQJlayWWuhE";
  assertEquals(actual, expected);
});

Deno.test("isJwtValid()", async () => {
  const jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
    "eyJpc3MiOiJmb3JleHNiLmNvbSIsImlhdCI6MTcyNTU0MDg3MiwiZXh" +
    "wIjoxNzU3MDc2ODcyLCJhdWQiOiJmb3JleHNiLmNvbS9lYS1zdHVkaW" +
    "8iLCJzdWIiOiJpbmZvQGZvcmV4c2IuY29tIn0." +
    "I0PqXCFyjlrFLgzTg_H2aPEbsOfPGNJJPwnLfG2KCe4";
  const key = "supersecret";
  const actual = await isJwtValid(jwt, key);
  isOk(actual);
});

Deno.test("getJwtPayload()", () => {
  const jwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9." +
    "eyJpc3MiOiJmb3JleHNiLmNvbSIsImlhdCI6MTcyNTU0MDg3MiwiZXh" +
    "wIjoxNzU3MDc2ODcyLCJhdWQiOiJmb3JleHNiLmNvbS9lYS1zdHVkaW" +
    "8iLCJzdWIiOiJpbmZvQGZvcmV4c2IuY29tIn0." +
    "I0PqXCFyjlrFLgzTg_H2aPEbsOfPGNJJPwnLfG2KCe4";
  const actual = getJwtPayload(jwt);
  const expected = {
    "iss": "forexsb.com",
    "iat": 1725540872,
    "exp": 1757076872,
    "aud": "forexsb.com/ea-studio",
    "sub": "info@forexsb.com",
  };
  assertEquals(JSON.stringify(actual), JSON.stringify(expected));
});

Deno.test("isJwtExpired() given not-expired", async () => {
  const nowSec = Math.floor(Date.now() / 1000);
  const payload = {
    "sub": "1234567890",
    "name": "John Doe",
    "iat": nowSec - 1000,
    "exp": nowSec + 1000,
  };
  const key = "qwertyuiopasdfghjklzxcvbnm123456";
  const jwt = await createJwt(payload, key);
  isOk(!isJwtExpired(jwt));
});

Deno.test("isJwtExpired() given expired", async () => {
  const nowSec = Math.floor(Date.now() / 1000);
  const payload = {
    "sub": "1234567890",
    "name": "John Doe",
    "iat": nowSec - 1000,
    "exp": nowSec - 100,
  };
  const key = "qwertyuiopasdfghjklzxcvbnm123456";
  const jwt = await createJwt(payload, key);
  isOk(isJwtExpired(jwt));
});
