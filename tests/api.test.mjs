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
  process.env.ADMIN_CODE = "un-code-de-test";
  process.env.SESSION_SECRET = "secret-de-test-assez-long-pour-la-session";
  const origin = "https://lecteurs.example";
  try {
    const unauthorized = await handler(new Request(`${origin}/api/inscriptions`));
    assert.equal(unauthorized.status, 401);

    const deniedOrigin = await handler(new Request(`${origin}/api/login`, {
      method: "POST", headers: { "content-type": "application/json", origin: "https://attacker.example" },
      body: JSON.stringify({ tel: "0700000000", code: "un-code-de-test" }),
    }));
    assert.equal(deniedOrigin.status, 403);

    const login = await handler(new Request(`${origin}/api/login`, {
      method: "POST", headers: { "content-type": "application/json", origin },
      body: JSON.stringify({ tel: "+225 07 00 00 00 00", code: "un-code-de-test" }),
    }));
    assert.equal(login.status, 200);
    assert.match(login.headers.get("set-cookie"), /HttpOnly/);
    assert.match(login.headers.get("set-cookie"), /SameSite=Strict/);
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});