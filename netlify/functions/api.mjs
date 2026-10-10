import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { getStore } from "@netlify/blobs";

const STORE_NAME = "lecteurs-inscriptions";
const COOKIE_NAME = "ndt_admin";
const SESSION_SECONDS = 60 * 60 * 8;
const MAX_BODY_BYTES = 10_000;
const MAX_RECORDS = 5_000;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 8;
const loginAttempts = new Map();

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers },
  });
}

function normalizePhone(value) {
  let digits = String(value ?? "").replace(/\D/g, "");
  if (digits.startsWith("00")) digits = digits.slice(2);
  if (digits.startsWith("225")) digits = digits.slice(3);
  return digits;
}

function configured(env = process.env) {
  return Boolean(
    env.ADMIN_PHONES?.trim() &&
    env.ADMIN_CODE?.trim() &&
    env.SESSION_SECRET &&
    env.SESSION_SECRET.length >= 32,
  );
}

function allowedPhones(env = process.env) {
  return new Set((env.ADMIN_PHONES ?? "").split(",").map(normalizePhone).filter(phone => /^\d{10}$/.test(phone)));
}

function constantTimeEqual(left, right) {
  const a = createHmac("sha256", "ndt-compare").update(String(left)).digest();
  const b = createHmac("sha256", "ndt-compare").update(String(right)).digest();
  return timingSafeEqual(a, b) && String(left) === String(right);
}

function sign(payload, secret) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac("sha256", secret).update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

function verify(token, secret) {
  if (!token || !secret) return null;
  const [encoded, supplied, extra] = token.split(".");
  if (!encoded || !supplied || extra) return null;
  const expected = createHmac("sha256", secret).update(encoded).digest();
  let actual;
  try { actual = Buffer.from(supplied, "base64url"); } catch { return null; }
  if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
    return payload.exp > Math.floor(Date.now() / 1000) && typeof payload.phone === "string" ? payload : null;
  } catch { return null; }
}

function session(request, env = process.env) {
  const cookie = request.headers.get("cookie") ?? "";
  const token = cookie.split(";").map(part => part.trim()).find(part => part.startsWith(`${COOKIE_NAME}=`))?.slice(COOKIE_NAME.length + 1);
  const payload = verify(token, env.SESSION_SECRET);
  return payload && allowedPhones(env).has(payload.phone) ? payload : null;
}

function cookieHeader(token, maxAge) {
  return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

function sameOrigin(request) {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  try { return new URL(origin).host === new URL(request.url).host; } catch { return false; }
}

export function validateRegistration(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  const section = input.section;
  if (section !== "Adultes" && section !== "Enfants") return null;
  const nom = String(input.nom ?? "").trim();
  const prenoms = String(input.prenoms ?? "").trim();
  const tel = String(input.tel ?? "").trim();
  const parent = section === "Enfants" ? String(input.parent ?? "").trim() : "";
  const age = section === "Enfants" ? String(input.age ?? "").trim() : "";
  const quartier = String(input.quartier ?? "").trim();
  const motivation = String(input.motivation ?? "").trim();
  if (!nom || !prenoms || nom.length > 100 || prenoms.length > 120) return null;
  if (tel.replace(/\D/g, "").length < 8 || tel.length > 30) return null;
  if (section === "Enfants" && (!parent || parent.length > 160)) return null;
  if (age && (!/^\d{1,2}$/.test(age) || Number(age) > 18)) return null;
  if (quartier.length > 120 || motivation.length > 1000 || input.consent !== true || input.baptise !== true || input.communie !== true) return null;

  // Les données de baptême/communion servent uniquement à la vérification du formulaire,
  // elles ne sont pas conservées car elles révèlent des convictions religieuses.
  return { section, nom, prenoms, tel, parent, age, quartier, motivation, consent: true };
}

function csvCell(value) {
  let text = String(value ?? "");
  if (/^[\s]*[=+@\-]/.test(text)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}

export function registrationsCsv(entries) {
  const columns = ["createdAt", "section", "nom", "prenoms", "tel", "quartier", "parent", "age", "motivation"];
  return [columns.join(";"), ...entries.map(entry => columns.map(column => csvCell(entry[column])).join(";"))].join("\r\n");
}

function loginAttemptKey(request) {
  return request.headers.get("x-nf-client-connection-ip") ?? request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
}

async function readJson(request) {
  const text = await request.text();
  if (Buffer.byteLength(text, "utf8") > MAX_BODY_BYTES) return null;
  try { return JSON.parse(text); } catch { return null; }
}

function apiPath(request) {
  const pathname = new URL(request.url).pathname;
  const functionPrefix = "/.netlify/functions/api";
  if (pathname.startsWith(functionPrefix)) return pathname.slice(functionPrefix.length) || "/";
  return pathname.startsWith("/api/") ? pathname.slice(4) : pathname;
}

async function listEntries(store) {
  const { blobs } = await store.list({ prefix: "registration/" });
  const entries = await Promise.all(blobs.map(blob => store.get(blob.key, { type: "json" })));
  return entries.filter(Boolean).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export default async function handler(request) {
  const path = apiPath(request);
  const method = request.method.toUpperCase();
  const env = process.env;

  if (path === "/me" && method === "GET") {
    const isConfigured = configured(env);
    return json({ admin: Boolean(isConfigured && session(request, env)), needsCode: true, configured: isConfigured });
  }

  if (!configured(env)) return json({ error: "Le service n'est pas encore configuré." }, 503);
  if (method !== "GET" && !sameOrigin(request)) return json({ error: "Origine refusée." }, 403);

  if (path === "/login" && method === "POST") {
    const key = loginAttemptKey(request);
    const now = Date.now();
    const previous = loginAttempts.get(key);
    if (previous && previous.until > now && previous.count >= MAX_LOGIN_ATTEMPTS) {
      return json({ error: "Trop de tentatives. Réessaie dans quelques minutes." }, 429, {
        "retry-after": String(Math.ceil((previous.until - now) / 1000)),
      });
    }
    const input = await readJson(request);
    if (!input) return json({ error: "Requête invalide." }, 400);
    const phone = normalizePhone(input.tel);
    if (!allowedPhones(env).has(phone) || !constantTimeEqual(input.code ?? "", env.ADMIN_CODE)) {
      const state = previous && previous.until > now ? previous : { count: 0, until: now + LOGIN_WINDOW_MS };
      state.count += 1;
      loginAttempts.set(key, state);
      return json({ error: "Identifiants incorrects." }, 401);
    }
    loginAttempts.delete(key);
    const token = sign({ phone, exp: Math.floor(Date.now() / 1000) + SESSION_SECONDS }, env.SESSION_SECRET);
    return json({ ok: true }, 200, { "set-cookie": cookieHeader(token, SESSION_SECONDS) });
  }

  if (path === "/logout" && method === "POST") {
    return json({ ok: true }, 200, { "set-cookie": cookieHeader("", 0) });
  }

  if (path === "/inscriptions" && method === "POST") {
    const input = await readJson(request);
    const entry = validateRegistration(input);
    if (!entry) return json({ error: "Vérifie les champs obligatoires et le consentement." }, 400);
    try {
      const store = getStore(STORE_NAME);
      const { blobs } = await store.list({ prefix: "registration/" });
      if (blobs.length >= MAX_RECORDS) return json({ error: "La liste est momentanément pleine." }, 503);
      entry.createdAt = new Date().toISOString();
      entry.id = randomUUID();
      await store.setJSON(`registration/${entry.id}`, entry);
      return json({ ok: true, id: entry.id }, 201);
    } catch {
      return json({ error: "Impossible d'enregistrer pour le moment." }, 503);
    }
  }

  if (path === "/inscriptions" && method === "GET") {
    if (!session(request, env)) return json({ error: "Authentification requise." }, 401);
    try { return json(await listEntries(getStore(STORE_NAME))); }
    catch { return json({ error: "Impossible de charger la liste." }, 503); }
  }

  if (path === "/inscriptions.csv" && method === "GET") {
    if (!session(request, env)) return json({ error: "Authentification requise." }, 401);
    try {
      const contents = `\ufeff${registrationsCsv(await listEntries(getStore(STORE_NAME)))}`;
      return new Response(contents, {
        headers: {
          "content-type": "text/csv; charset=utf-8",
          "content-disposition": 'attachment; filename="inscriptions-lecteurs-ndt.csv"',
          "cache-control": "no-store",
        },
      });
    } catch { return json({ error: "Impossible de préparer l'export." }, 503); }
  }

  return json({ error: "Route introuvable." }, 404);
}