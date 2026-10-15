import test from "node:test";
import assert from "node:assert/strict";
import handler, { registrationsCsv, validateRegistration } from "../netlify/functions/api.mjs";

test("valide et normalise une inscription adulte sans conserver les données sensibles", () => {
  const entry = validateRegistration({
    section: "Adultes", nom: "Kouassi", prenoms: "Awa", tel: "+225 07 00 00 00 00",
    baptise: true, communie: true, consent: true,
  });
  assert.equal(entry.nom, "Kouassi");
  assert.equal("baptise" in entry, false);
  assert.equal("communie" in entry, false);
});

test("exige parent et consentement pour une inscription enfant", () => {
  assert.equal(validateRegistration({ section: "Enfants", nom: "Kouassi", prenoms: "Awa", tel: "0700000000", consent: true }), null);
  assert.equal(validateRegistration({ section: "Adultes", nom: "Kouassi", prenoms: "Awa", tel: "0700000000" }), null);
  assert.equal(validateRegistration({ section: "Adultes", nom: "Kouassi", prenoms: "Awa", tel: "0700000000", consent: true, baptise: false, communie: true }), null);
});

test("protège l'export CSV contre les cellules exécutables", () => {
  const csv = registrationsCsv([{ createdAt: "2026-10-10", section: "Adultes", nom: "=HYPERLINK(\"https://example.com\")" }]);
  assert.match(csv, /'=HYPERLINK/);
  assert.match(csv, /createdAt;section;nom/);
});

test("protège les routes responsables et crée une session avec les bons identifiants", async () => {
  const previous = {
    ADMIN_PHONES: process.env.ADMIN_PHONES,
    ADMIN_CODE: process.env.ADMIN_CODE,
    SESSION_SECRET: process.env.SESSION_SECRET,
  };
  process.env.ADMIN_PHONES = "0700000000";
  process.env.ADMIN_CODE = "un-code-de-test-avec-une-longueur-suffisante";
  process.env.SESSION_SECRET = "secret-de-test-assez-long-pour-la-session";
  const origin = "https://lecteurs.example";
  try {
    const unauthorized = await handler(new Request(`${origin}/api/inscriptions`));
    assert.equal(unauthorized.status, 401);

    const deniedOrigin = await handler(new Request(`${origin}/api/login`, {
      method: "POST", headers: { "content-type": "application/json", origin: "https://attacker.example" },
      body: JSON.stringify({ tel: "0700000000", code: process.env.ADMIN_CODE }),
    }));
    assert.equal(deniedOrigin.status, 403);

    const deniedScheme = await handler(new Request(`${origin}/api/login`, {
      method: "POST", headers: { "content-type": "application/json", origin: "http://lecteurs.example" },
      body: JSON.stringify({ tel: "0700000000", code: process.env.ADMIN_CODE }),
    }));
    assert.equal(deniedScheme.status, 403);

    const invalidContentType = await handler(new Request(`${origin}/api/login`, {
      method: "POST", headers: { "content-type": "text/plain", origin },
      body: JSON.stringify({ tel: "0700000000", code: "un-code-de-test" }),
    }));
    assert.equal(invalidContentType.status, 400);

    const oversized = await handler(new Request(`${origin}/api/login`, {
      method: "POST",
      headers: { "content-type": "application/json", origin, "x-nf-client-connection-ip": "203.0.113.2" },
      body: JSON.stringify({ tel: "0700000000", code: "x".repeat(10_000) }),
    }));
    assert.equal(oversized.status, 400);

    const login = await handler(new Request(`${origin}/api/login`, {
      method: "POST", headers: { "content-type": "application/json", origin },
      body: JSON.stringify({ tel: "+225 07 00 00 00 00", code: process.env.ADMIN_CODE }),
    }));
    assert.equal(login.status, 200);
    assert.match(login.headers.get("set-cookie"), /HttpOnly/);
    assert.match(login.headers.get("set-cookie"), /SameSite=Strict/);
    assert.equal(login.headers.get("x-content-type-options"), "nosniff");
    assert.equal(login.headers.get("strict-transport-security"), "max-age=31536000");

    const rateLimitIp = "203.0.113.8";
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const denied = await handler(new Request(`${origin}/api/login`, {
        method: "POST",
        headers: { "content-type": "application/json", origin, "x-nf-client-connection-ip": rateLimitIp },
        body: JSON.stringify({ tel: "0700000000", code: "mauvais-code" }),
      }));
      assert.equal(denied.status, 401);
    }
    const rateLimited = await handler(new Request(`${origin}/api/login`, {
      method: "POST",
      headers: { "content-type": "application/json", origin, "x-nf-client-connection-ip": rateLimitIp },
      body: JSON.stringify({ tel: "0700000000", code: "mauvais-code" }),
    }));
    assert.equal(rateLimited.status, 429);
    assert.ok(Number(rateLimited.headers.get("retry-after")) > 0);

    for (let attempt = 0; attempt < 8; attempt += 1) {
      const denied = await handler(new Request(`${origin}/api/login`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin,
          "x-forwarded-for": `198.51.100.${attempt + 1}`,
        },
        body: JSON.stringify({ tel: "0700000000", code: "mauvais-code" }),
      }));
      assert.equal(denied.status, 401);
    }
    const spoofedIpRateLimited = await handler(new Request(`${origin}/api/login`, {
      method: "POST",
      headers: { "content-type": "application/json", origin, "x-forwarded-for": "192.0.2.99" },
      body: JSON.stringify({ tel: "0700000000", code: "mauvais-code" }),
    }));
    assert.equal(spoofedIpRateLimited.status, 429);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

test("refuse la configuration responsable avec un code trop court ou réutilisé comme secret de session", async () => {
  const previous = {
    ADMIN_PHONES: process.env.ADMIN_PHONES,
    ADMIN_CODE: process.env.ADMIN_CODE,
    SESSION_SECRET: process.env.SESSION_SECRET,
  };
  process.env.ADMIN_PHONES = "0700000000";
  process.env.SESSION_SECRET = "un-secret-de-session-suffisamment-long-pour-les-tests";
  try {
    process.env.ADMIN_CODE = "trop-court";
    const shortCodeResponse = await handler(new Request("https://lecteurs.example/api/me"));
    assert.equal((await shortCodeResponse.json()).configured, false);

    process.env.ADMIN_CODE = process.env.SESSION_SECRET;
    const reusedSecretResponse = await handler(new Request("https://lecteurs.example/api/me"));
    assert.equal((await reusedSecretResponse.json()).configured, false);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});