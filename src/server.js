const express = require("express");
const path = require("path");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { processComment } = require("./brain");
const pool = require("./db");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── config ──────────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me-please";
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || "joemaina242@gmail.com").trim().toLowerCase();
const ADMIN_CODE = process.env.ADMIN_CODE || "admin123";
const APP_BASE = (process.env.APP_BASE_URL || "http://localhost:3000").replace(/\/$/, "");
const TK = {
  key: process.env.TIKTOK_CLIENT_KEY || "",
  secret: process.env.TIKTOK_CLIENT_SECRET || "",
  redirect: process.env.TIKTOK_REDIRECT_URI || (APP_BASE + "/api/tiktok/callback"),
};
if (!process.env.JWT_SECRET) console.warn("⚠️  JWT_SECRET not set — using dev secret.");
function encKey() {
  if (process.env.ENCRYPTION_KEY && process.env.ENCRYPTION_KEY.length === 64) return Buffer.from(process.env.ENCRYPTION_KEY, "hex");
  return crypto.createHash("sha256").update(JWT_SECRET + "|jibuflow").digest();
}

// ─── crash protection ────────────────────────────────────────────────────────
process.on("uncaughtException", (e) => console.error("\n❌ UNCAUGHT (kept alive):", e.message));
process.on("unhandledRejection", (e) => console.error("\n❌ UNHANDLED REJECTION (kept alive):", e));

// ─── crypto ──────────────────────────────────────────────────────────────────
function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", encKey(), iv);
  const enc = Buffer.concat([c.update(String(plain), "utf8"), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), enc]);
}
function decrypt(buf) {
  if (!buf) return "";
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  const iv = b.subarray(0, 12), tag = b.subarray(12, 28), ct = b.subarray(28);
  const d = crypto.createDecipheriv("aes-256-gcm", encKey(), iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]).toString("utf8");
}
const signState = (obj) => {
  const payload = Buffer.from(JSON.stringify(obj)).toString("base64url");
  const mac = crypto.createHmac("sha256", JWT_SECRET).update(payload).digest("hex");
  return payload + "." + mac;
};
const verifyState = (s) => {
  const [payload, mac] = String(s || "").split(".");
  if (!payload || !mac) return null;
  const ok = crypto.createHmac("sha256", JWT_SECRET).update(payload).digest("hex");
  try { if (!crypto.timingSafeEqual(Buffer.from(mac, "hex"), Buffer.from(ok, "hex"))) return null; } catch { return null; }
  try { return JSON.parse(Buffer.from(payload, "base64url").toString("utf8")); } catch { return null; }
};

// ─── auth ─────────────────────────────────────────────────────────────────
const signToken = (acc) => jwt.sign({ sub: acc.id, role: acc.role }, JWT_SECRET, { expiresIn: "7d" });
async function requireAuth(req, res, next) {
  const h = req.headers.authorization || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!t) return res.status(401).json({ error: "Not signed in" });
  try {
    const p = jwt.verify(t, JWT_SECRET);
    const r = await pool.query("SELECT id,name,email,business,brand_context,whatsapp,plan,role,account_status,token_revoked_at FROM accounts WHERE id=$1", [p.sub]);
    const a = r.rows[0];
    if (!a) return res.status(401).json({ error: "Account not found" });
    if (a.account_status === "banned") return res.status(403).json({ error: "Account banned" });
    if (a.account_status === "suspended") return res.status(403).json({ error: "Account suspended" });
    if (a.token_revoked_at && (!p.iat || p.iat * 1000 <= new Date(a.token_revoked_at).getTime())) return res.status(401).json({ error: "Session revoked" });
    req.account = a; next();
  } catch { return res.status(401).json({ error: "Bad or expired token" }); }
}
function requireOwner(req, res, next) {
  if (req.account && req.account.role === "owner") return next();
  return res.status(403).json({ error: "Owner only" });
}

// ─── mappers ─────────────────────────────────────────────────────────────────
const PLAN_LABEL = { starter: "Starter", pro_trial: "Pro trial", pro: "Pro", scale: "Scale" };
function fmtDate(d) {
  if (!d) return "";
  const dt = new Date(d);
  if (Date.now() - dt.getTime() < 120000) return "Just now";
  return dt.toLocaleDateString("en-US", { month: "short", day: "2-digit", year: "numeric" });
}
function postToUI(r) {
  let conv;
  if ((r.impressions || 0) > 0) conv = Math.round((100 * (r.conversions || 0)) / r.impressions * 10) / 10;
  else if ((r.comments_count || 0) > 0) conv = Math.round((100 * (r.intent_count || 0)) / r.comments_count * 10) / 10;
  else conv = 0;
  return {
    id: r.id, owner: r.owner_name || "", title: r.title || "TikTok post", link: r.link,
    date: fmtDate(r.created_at), comments: r.comments_count || 0, intent: r.intent_count || 0,
    replies: r.replies_count || 0, conv: conv + "%",
  };
}
function userToUI(a, tik) {
  return {
    id: a.id, name: a.name, email: a.email, business: a.business || "",
    plan: PLAN_LABEL[a.plan] || a.plan, role: a.role, status: a.account_status || "active",
    tiktok: tik ? { connected: true, handle: tik.handle } : { connected: false },
  };
}
const isoDate = (d) => d.toISOString().slice(0, 10);
const isOwnerEmail = (e) => String(e || "").trim().toLowerCase() === ADMIN_EMAIL;

// ═══════════════════════════════════════════════════════════════════════════
//  SCHEMA — idempotent + SELF-HEALING (repairs old tables on boot)
// ═══════════════════════════════════════════════════════════════════════════
const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS users ( tiktok_username TEXT PRIMARY KEY, last_seen_at TIMESTAMPTZ DEFAULT NOW() );
CREATE TABLE IF NOT EXISTS memory_logs (
  id SERIAL PRIMARY KEY, tiktok_username TEXT NOT NULL REFERENCES users(tiktok_username) ON DELETE CASCADE,
  fact_key TEXT NOT NULL, fact_value TEXT NOT NULL, confidence INT DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW(), UNIQUE (tiktok_username, fact_key)
);
CREATE TABLE IF NOT EXISTS interactions (
  id SERIAL PRIMARY KEY, tiktok_username TEXT NOT NULL, comment TEXT, reply TEXT, intent TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE interactions ADD COLUMN IF NOT EXISTS account_id UUID;
ALTER TABLE interactions ADD COLUMN IF NOT EXISTS post_id UUID;
CREATE INDEX IF NOT EXISTS interactions_account_idx ON interactions(account_id);

CREATE TABLE IF NOT EXISTS accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
  password_hash TEXT, google_sub TEXT, business TEXT, brand_context TEXT, whatsapp TEXT,
  plan TEXT NOT NULL DEFAULT 'pro_trial', role TEXT NOT NULL DEFAULT 'user',
  account_status TEXT NOT NULL DEFAULT 'active', token_revoked_at TIMESTAMPTZ,
  trial_ends_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '14 days'), created_at TIMESTAMPTZ DEFAULT NOW()
);
/* SELF-HEAL: add any column an older schema is missing (this is what fixes the signup crash) */
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS password_hash TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS google_sub TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS business TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS brand_context TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS whatsapp TEXT;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS plan TEXT NOT NULL DEFAULT 'pro_trial';
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user';
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS account_status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS token_revoked_at TIMESTAMPTZ;
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS trial_ends_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '14 days');

CREATE TABLE IF NOT EXISTS tiktok_connections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  tiktok_open_id TEXT NOT NULL UNIQUE, handle TEXT, access_token_enc BYTEA NOT NULL, refresh_token_enc BYTEA,
  token_expires_at TIMESTAMPTZ, scopes TEXT[], dm_available BOOLEAN NOT NULL DEFAULT FALSE,
  connected_at TIMESTAMPTZ DEFAULT NOW(), revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS posts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  tiktok_video_id TEXT, link TEXT NOT NULL, title TEXT, business TEXT, context TEXT, phone TEXT,
  status TEXT NOT NULL DEFAULT 'active', comments_count INT NOT NULL DEFAULT 0, intent_count INT NOT NULL DEFAULT 0,
  replies_count INT NOT NULL DEFAULT 0, conversions INT NOT NULL DEFAULT 0, impressions INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
ALTER TABLE posts ADD COLUMN IF NOT EXISTS title TEXT;
ALTER TABLE posts ADD COLUMN IF NOT EXISTS business TEXT;
ALTER TABLE posts ADD COLUMN IF NOT EXISTS context TEXT;
ALTER TABLE posts ADD COLUMN IF NOT EXISTS phone TEXT;
ALTER TABLE posts ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE posts ADD COLUMN IF NOT EXISTS comments_count INT NOT NULL DEFAULT 0;
ALTER TABLE posts ADD COLUMN IF NOT EXISTS intent_count INT NOT NULL DEFAULT 0;
ALTER TABLE posts ADD COLUMN IF NOT EXISTS replies_count INT NOT NULL DEFAULT 0;
ALTER TABLE posts ADD COLUMN IF NOT EXISTS conversions INT NOT NULL DEFAULT 0;
ALTER TABLE posts ADD COLUMN IF NOT EXISTS impressions INT NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS posts_account_idx ON posts(account_id);
CREATE OR REPLACE VIEW post_metrics AS
  SELECT p.*, CASE WHEN impressions > 0 THEN ROUND(100.0 * conversions / impressions, 1) ELSE 0 END AS conversion_rate
  FROM posts p;

CREATE TABLE IF NOT EXISTS announcements (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), type TEXT NOT NULL DEFAULT 'info',
  title TEXT NOT NULL, msg TEXT NOT NULL, revoked BOOLEAN NOT NULL DEFAULT FALSE, created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS audit_log (
  id SERIAL PRIMARY KEY, actor_email TEXT, action TEXT NOT NULL, detail TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS failed_auth (
  id SERIAL PRIMARY KEY, source TEXT, note TEXT, ip TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(), label TEXT NOT NULL, type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued', account_email TEXT, created_at TIMESTAMPTZ DEFAULT NOW(), updated_at TIMESTAMPTZ DEFAULT NOW()
);
`;
async function ensureSchema() {
  try { await pool.query(SCHEMA_SQL); console.log("✅ Schema ready + self-healed (accounts, AI memory, admin ops)"); }
  catch (e) { console.error("❌ Schema error:", e.message); }
}
async function ensureOwner() {
  try {
    const r = await pool.query("UPDATE accounts SET role='owner' WHERE lower(email)=$1 RETURNING id", [ADMIN_EMAIL]);
    if (r.rowCount > 0) console.log("👑 Owner ensured for " + ADMIN_EMAIL);
    else console.log("ℹ️  Owner account not created yet — it will auto-promote on signup/Google for " + ADMIN_EMAIL);
  } catch (e) { console.error("ensureOwner:", e.message); }
}
async function audit(actorEmail, action, detail) {
  try { await pool.query("INSERT INTO audit_log (actor_email,action,detail) VALUES ($1,$2,$3)", [actorEmail || "system", action, detail || ""]); } catch (e) {}
}
async function logFailed(source, note, ip) {
  try { await pool.query("INSERT INTO failed_auth (source,note,ip) VALUES ($1,$2,$3)", [source, note, ip || ""]); } catch (e) {}
}

// ─── static UI (serves public/index.html at the ngrok root) ──────────────────
app.use(express.static(path.join(__dirname, "..", "public")));

// ─── health + config ─────────────────────────────────────────────────────────
app.get("/health", async (req, res) => {
  try { await pool.query("SELECT 1"); res.json({ status: "ok", db: "connected ✅" }); }
  catch (e) { res.status(500).json({ status: "error", db: "❌ " + e.message }); }
});
app.get("/api/health", (req, res) => res.json({ status: "JibuFlow API alive ✅", time: new Date() }));
app.get("/api/config", (req, res) => res.json({ googleClientId: process.env.GOOGLE_CLIENT_ID || "", adminEmail: ADMIN_EMAIL }));

// ═══════════════════════════════════════════════════════════════════════════
//  AUTH
// ═══════════════════════════════════════════════════════════════════════════
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || !email || !password) return res.status(400).json({ error: "name, email and password required" });
    if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
    const hash = await bcrypt.hash(password, 10);
    const role = isOwnerEmail(email) ? "owner" : "user";
    const r = await pool.query(
      `INSERT INTO accounts (name,email,password_hash,role) VALUES ($1,$2,$3,$4)
       ON CONFLICT (email) DO NOTHING RETURNING id,name,email,business,plan,role,account_status`,
      [name.trim(), email.trim().toLowerCase(), hash, role]
    );
    if (!r.rows[0]) return res.status(409).json({ error: "An account with that email already exists — try logging in." });
    await audit(r.rows[0].email, "Account created", role === "owner" ? "auto-promoted owner" : "");
    res.json({ token: signToken(r.rows[0]), user: userToUI(r.rows[0], null) });
  } catch (e) { console.error("signup", e); res.status(500).json({ error: e.message }); }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const em = String(email || "").trim().toLowerCase();
    const r = await pool.query("SELECT id,name,email,password_hash,business,plan,role,account_status,token_revoked_at FROM accounts WHERE email=$1", [em]);
    if (!r.rows[0]) { await logFailed("Login", "Unknown email: " + em, req.ip); return res.status(401).json({ error: "Invalid email or password" }); }
    const a = r.rows[0];
    const ok = a.password_hash && await bcrypt.compare(password || "", a.password_hash);
    if (!ok) { await logFailed("Login", "Wrong password: " + em, req.ip); return res.status(401).json({ error: "Invalid email or password" }); }
    if (a.account_status === "banned") return res.status(403).json({ error: "Account banned" });
    if (a.account_status === "suspended") return res.status(403).json({ error: "Account suspended" });
    const tik = await pool.query("SELECT handle FROM tiktok_connections WHERE account_id=$1 AND revoked_at IS NULL LIMIT 1", [a.id]);
    res.json({ token: signToken(a), user: userToUI(a, tik.rows[0]) });
  } catch (e) { console.error("login", e); res.status(500).json({ error: e.message }); }
});

app.post("/api/auth/google", async (req, res) => {
  try {
    const { credential } = req.body || {};
    if (!credential) return res.status(400).json({ error: "Missing Google credential" });
    let OAuth2Client;
    try { ({ OAuth2Client } = require("google-auth-library")); } catch { return res.status(501).json({ error: "Google sign-in not configured on server" }); }
    if (!process.env.GOOGLE_CLIENT_ID) return res.status(501).json({ error: "GOOGLE_CLIENT_ID not set" });
    const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
    const ticket = await client.verifyIdToken({ idToken: credential, audience: process.env.GOOGLE_CLIENT_ID });
    const p = ticket.getPayload();
    const email = (p.email || "").toLowerCase();
    const role = isOwnerEmail(email) ? "owner" : "user";
    let r = await pool.query("SELECT id,name,email,business,plan,role,account_status,google_sub FROM accounts WHERE google_sub=$1 OR email=$2", [p.sub, email]);
    if (!r.rows[0]) {
      r = await pool.query(`INSERT INTO accounts (name,email,google_sub,role) VALUES ($1,$2,$3,$4) RETURNING id,name,email,business,plan,role,account_status`, [p.name || p.given_name || email, email, p.sub, role]);
      await audit(email, "Account created (Google)", role === "owner" ? "auto-promoted owner" : "");
    } else {
      if (!r.rows[0].google_sub) await pool.query("UPDATE accounts SET google_sub=$1 WHERE id=$2", [p.sub, r.rows[0].id]);
      if (r.rows[0].role !== role && role === "owner") { await pool.query("UPDATE accounts SET role='owner' WHERE id=$1", [r.rows[0].id]); r.rows[0].role = "owner"; }
    }
    res.json({ token: signToken(r.rows[0]), user: userToUI(r.rows[0], null) });
  } catch (e) { console.error("google", e); res.status(401).json({ error: "Google verification failed" }); }
});

app.get("/api/auth/me", requireAuth, async (req, res) => {
  const tik = await pool.query("SELECT handle FROM tiktok_connections WHERE account_id=$1 AND revoked_at IS NULL LIMIT 1", [req.account.id]);
  res.json({ user: userToUI(req.account, tik.rows[0]) });
});
app.post("/api/auth/logout", (req, res) => res.json({ ok: true }));

app.patch("/api/auth/profile", requireAuth, async (req, res) => {
  const { name, biz, ctx, phone } = req.body || {};
  await pool.query(
    `UPDATE accounts SET
       name=COALESCE(NULLIF($1,''),name),
       business=COALESCE(NULLIF($2,''),business),
       brand_context=COALESCE(NULLIF($3,''),brand_context),
       whatsapp=COALESCE(NULLIF($4,''),whatsapp)
     WHERE id=$5`,
    [name, biz, ctx, phone, req.account.id]
  );
  const r = await pool.query("SELECT id,name,email,business,plan,role,account_status FROM accounts WHERE id=$1", [req.account.id]);
  res.json({ user: userToUI(r.rows[0], null) });
});
app.post("/api/auth/password", requireAuth, async (req, res) => {
  const { password } = req.body || {};
  if (!password || password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
  const hash = await bcrypt.hash(password, 10);
  await pool.query("UPDATE accounts SET password_hash=$1, token_revoked_at=NOW() WHERE id=$2", [hash, req.account.id]);
  await audit(req.account.email, "Password changed");
  res.json({ ok: true });
});
app.delete("/api/auth/sessions", requireAuth, async (req, res) => {
  await pool.query("UPDATE accounts SET token_revoked_at=NOW() WHERE id=$1", [req.account.id]);
  await audit(req.account.email, "All sessions revoked (self)");
  res.json({ ok: true });
});
app.delete("/api/auth/account", requireAuth, async (req, res) => {
  await pool.query("DELETE FROM accounts WHERE id=$1", [req.account.id]);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════════════
//  TIKTOK OAUTH
// ═══════════════════════════════════════════════════════════════════════════
app.get("/api/tiktok/authorize", requireAuth, (req, res) => {
  if (!TK.key) return res.status(501).json({ error: "TIKTOK_CLIENT_KEY not configured" });
  const state = signState({ accountId: req.account.id, origin: APP_BASE, nonce: crypto.randomBytes(8).toString("hex") });
  const url = "https://www.tiktok.com/v2/auth/authorize/?" + new URLSearchParams({
    client_key: TK.key, response_type: "code", scope: "user.info.basic,video.list", redirect_uri: TK.redirect, state,
  }).toString();
  res.json({ url });
});
app.get("/api/tiktok/callback", async (req, res) => {
  const home = (verifyState(req.query.state) || {}).origin || APP_BASE;
  const fail = (m) => res.redirect(home + "/?connected=0&error=" + encodeURIComponent(m));
  try {
    const st = verifyState(req.query.state);
    if (!st || !st.accountId) return fail("bad state");
    const code = req.query.code;
    if (!code) return fail(req.query.error_description || "no code");
    const tokRes = await fetch("https://open.tiktokapis.com/v2/oauth/token/", {
      method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_key: TK.key, client_secret: TK.secret, code, grant_type: "authorization_code", redirect_uri: TK.redirect }).toString(),
    });
    const tok = await tokRes.json();
    if (!tok.access_token) return fail(tok.error_description || tok.error || "token exchange failed");
    let handle = "";
    try {
      const me = await fetch("https://open.tiktokapis.com/v2/user/info/?fields=open_id,username,display_name", { headers: { Authorization: "Bearer " + tok.access_token } });
      const mj = await me.json();
      handle = (mj.data && mj.data.user && (mj.data.user.username || mj.data.user.display_name)) || "";
    } catch {}
    const openId = tok.open_id || crypto.randomBytes(8).toString("hex");
    const scopes = String(tok.scope || "").split(/[\s,]+/).filter(Boolean);
    const expiresAt = tok.expires_in ? new Date(Date.now() + tok.expires_in * 1000) : null;
    await pool.query(
      `INSERT INTO tiktok_connections (account_id,tiktok_open_id,handle,access_token_enc,refresh_token_enc,token_expires_at,scopes,dm_available)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (tiktok_open_id) DO UPDATE SET handle=EXCLUDED.handle, access_token_enc=EXCLUDED.access_token_enc,
         refresh_token_enc=EXCLUDED.refresh_token_enc, token_expires_at=EXCLUDED.token_expires_at, scopes=EXCLUDED.scopes, revoked_at=NULL, connected_at=NOW()`,
      [st.accountId, openId, handle, encrypt(tok.access_token), tok.refresh_token ? encrypt(tok.refresh_token) : null, expiresAt, scopes, false]
    );
    res.redirect(home + "/?connected=1&handle=" + encodeURIComponent(handle || "@connected"));
  } catch (e) { console.error("callback", e); fail("server error"); }
});
app.get("/api/tiktok/status", requireAuth, async (req, res) => {
  const r = await pool.query("SELECT handle,scopes,dm_available,token_expires_at,revoked_at FROM tiktok_connections WHERE account_id=$1 AND revoked_at IS NULL LIMIT 1", [req.account.id]);
  if (!r.rows[0]) return res.json({ connected: false, handle: "", scopes: [], dm_available: false });
  const expired = r.rows[0].token_expires_at && new Date(r.rows[0].token_expires_at) < new Date();
  res.json({ connected: true, handle: r.rows[0].handle, scopes: r.rows[0].scopes || [], dm_available: r.rows[0].dm_available, status: expired ? "expired" : "ok" });
});
app.post("/api/tiktok/disconnect", requireAuth, async (req, res) => {
  await pool.query("UPDATE tiktok_connections SET revoked_at=NOW() WHERE account_id=$1", [req.account.id]);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════════════
//  POSTS
// ═══════════════════════════════════════════════════════════════════════════
app.get("/api/posts", requireAuth, async (req, res) => {
  const r = await pool.query("SELECT * FROM post_metrics WHERE account_id=$1 ORDER BY created_at DESC", [req.account.id]);
  res.json(r.rows.map(postToUI));
});
app.post("/api/posts", requireAuth, async (req, res) => {
  try {
    const { link, business, context, phone } = req.body || {};
    if (!link) return res.status(400).json({ error: "link required" });
    await pool.query("UPDATE accounts SET business=COALESCE(NULLIF($1,''),business), brand_context=COALESCE(NULLIF($2,''),brand_context), whatsapp=COALESCE(NULLIF($3,''),whatsapp) WHERE id=$4", [business, context, phone, req.account.id]);
    const title = context ? String(context).split("\n")[0].slice(0, 60) : "TikTok post";
    const r = await pool.query(`INSERT INTO posts (account_id,link,title,business,context,phone) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`, [req.account.id, link, title, business || null, context || null, phone || null]);
    res.json(postToUI(r.rows[0]));
  } catch (e) { console.error("createPost", e); res.status(500).json({ error: e.message }); }
});
app.delete("/api/posts/:id", requireAuth, async (req, res) => {
  await pool.query("DELETE FROM posts WHERE id=$1 AND account_id=$2", [req.params.id, req.account.id]);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════════════
//  DASHBOARD — per-account, fully real
// ═══════════════════════════════════════════════════════════════════════════
async function winCounts(aId, f, t) {
  const r = await pool.query(
    `SELECT COUNT(*)::int AS comments,
            COUNT(*) FILTER (WHERE reply IS NOT NULL)::int AS replies,
            COUNT(*) FILTER (WHERE intent='high')::int AS intent,
            COUNT(*) FILTER (WHERE intent='high' AND reply IS NOT NULL)::int AS intent_replied
     FROM interactions WHERE account_id=$1 AND created_at >= $2 AND created_at <= $3`, [aId, f, t]);
  return r.rows[0];
}
function pct(c, p) { if (p > 0) return Math.round((100 * (c - p)) / p); return c > 0 ? 100 : 0; }
function dir(c, p) { return c > p ? "up" : c < p ? "down" : "flat"; }
app.get("/api/dashboard", requireAuth, async (req, res) => {
  try {
    const id = req.account.id;
    let fromD, toD;
    if (req.query.to) { toD = new Date(req.query.to + "T23:59:59"); } else { toD = new Date(); toD.setHours(23, 59, 59, 999); }
    if (req.query.from) { fromD = new Date(req.query.from + "T00:00:00"); } else { fromD = new Date(toD); fromD.setDate(fromD.getDate() - 6); fromD.setHours(0, 0, 0, 0); }
    const winMs = Math.max(0, toD - fromD);
    const prevTo = new Date(fromD.getTime() - 1);
    const prevFrom = new Date(prevTo.getTime() - winMs);
    const cur = await winCounts(id, fromD, toD);
    const prev = await winCounts(id, prevFrom, prevTo);
    const convCur = cur.comments > 0 ? Math.round((100 * cur.intent_replied) / cur.comments * 10) / 10 : 0;
    const convPrev = prev.comments > 0 ? Math.round((100 * prev.intent_replied) / prev.comments * 10) / 10 : 0;
    const stats = { comments: cur.comments, intent: cur.intent, replies: cur.replies, conversion: convCur };
    const deltas = {
      comments: { value: pct(cur.comments, prev.comments), dir: dir(cur.comments, prev.comments) },
      intent: { value: pct(cur.intent, prev.intent), dir: dir(cur.intent, prev.intent) },
      replies: { value: pct(cur.replies, prev.replies), dir: dir(cur.replies, prev.replies) },
      conv: { value: pct(convCur, convPrev), dir: dir(convCur, convPrev) },
    };
    const grp = await pool.query("SELECT created_at::date AS d, COUNT(*) FILTER (WHERE reply IS NOT NULL)::int v FROM interactions WHERE account_id=$1 AND created_at >= $2 AND created_at <= $3 GROUP BY d", [id, fromD, toD]);
    const byDay = {}; grp.rows.forEach((r) => { byDay[r.d.toISOString().slice(0, 10)] = r.v; });
    const labels = [], values = [];
    const cursor = new Date(fromD); cursor.setHours(0, 0, 0, 0);
    const endDay = new Date(toD); endDay.setHours(0, 0, 0, 0);
    const span = Math.round((endDay - cursor) / 86400000) + 1;
    const useWeekday = span <= 8;
    while (cursor <= endDay) {
      values.push(byDay[isoDate(cursor)] || 0);
      labels.push(useWeekday ? cursor.toLocaleDateString("en-US", { weekday: "short" }) : cursor.toLocaleDateString("en-US", { month: "short", day: "numeric" }));
      cursor.setDate(cursor.getDate() + 1);
    }
    const tp = await pool.query("SELECT * FROM post_metrics WHERE account_id=$1 ORDER BY intent_count DESC, replies_count DESC LIMIT 4", [id]);
    const mp = await pool.query("SELECT * FROM post_metrics WHERE account_id=$1 ORDER BY created_at DESC", [id]);
    res.json({ stats, deltas, series: { labels, values }, topPosts: tp.rows.map(postToUI), myPosts: mp.rows.map(postToUI) });
  } catch (e) { console.error("dashboard", e); res.status(500).json({ error: e.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════
//  ANNOUNCEMENTS (banner)
// ═══════════════════════════════════════════════════════════════════════════
app.get("/api/announcements", requireAuth, async (req, res) => {
  const r = await pool.query("SELECT id,type,title,msg,created_at FROM announcements WHERE revoked=FALSE ORDER BY created_at DESC LIMIT 5");
  res.json(r.rows);
});

// ═══════════════════════════════════════════════════════════════════════════
//  ADMIN — read (owner only)
// ═══════════════════════════════════════════════════════════════════════════
function tkStatus(row) {
  if (!row) return { connected: false, status: "none", handle: "", last_sync: "", api_today: 0 };
  if (row.revoked_at) return { connected: false, status: "revoked", handle: row.handle || "", last_sync: fmtDate(row.connected_at), api_today: row.api_today || 0 };
  const expired = row.token_expires_at && new Date(row.token_expires_at) < new Date();
  return { connected: true, status: expired ? "expired" : "ok", handle: row.handle || "", last_sync: fmtDate(row.connected_at), api_today: row.api_today || 0 };
}
app.get("/api/admin/summary", requireAuth, requireOwner, async (req, res) => {
  const u = await pool.query("SELECT COUNT(*)::int v FROM accounts");
  const p = await pool.query("SELECT COUNT(*)::int v FROM posts");
  const a = await pool.query("SELECT COUNT(*)::int v FROM posts WHERE status='active'");
  res.json({ users: u.rows[0].v, posts: p.rows[0].v, automations: a.rows[0].v, revenue_mtd: "$0" });
});
app.get("/api/admin/users", requireAuth, requireOwner, async (req, res) => {
  const today = await pool.query("SELECT account_id, COUNT(*)::int v FROM interactions WHERE account_id IS NOT NULL AND created_at >= CURRENT_DATE GROUP BY account_id");
  const apiMap = {}; today.rows.forEach((r) => { apiMap[r.account_id] = r.v; });
  const r = await pool.query(`SELECT a.id,a.name,a.email,a.business,a.plan,a.role,a.account_status,a.trial_ends_at,a.created_at,
     (SELECT COUNT(*)::int FROM posts p WHERE p.account_id=a.id) AS posts
     FROM accounts a ORDER BY a.created_at DESC`);
  const tkRows = await pool.query("SELECT account_id, handle, token_expires_at, connected_at, revoked_at FROM tiktok_connections");
  const tkByAcc = {}; tkRows.rows.forEach((t) => { tkByAcc[t.account_id] = t; });
  const out = r.rows.map((x) => {
    const tk = tkByAcc[x.id]; const st = tkStatus(tk); st.api_today = apiMap[x.id] || 0;
    return {
      id: x.id, name: x.name, email: x.email, business: x.business || "—", plan: PLAN_LABEL[x.plan] || x.plan,
      role: x.role, status: x.account_status || "active", joined: fmtDate(x.created_at), posts: x.posts,
      trial_ends_at: x.trial_ends_at, tiktok: st,
    };
  });
  res.json(out);
});
app.get("/api/admin/posts", requireAuth, requireOwner, async (req, res) => {
  const r = await pool.query(`SELECT pm.*, a.name AS owner_name FROM post_metrics pm JOIN accounts a ON a.id=pm.account_id ORDER BY pm.created_at DESC`);
  res.json(r.rows.map(postToUI));
});
app.get("/api/admin/announcements", requireAuth, requireOwner, async (req, res) => {
  const r = await pool.query("SELECT id,type,title,msg,revoked,created_at FROM announcements ORDER BY created_at DESC LIMIT 50");
  res.json(r.rows);
});
app.get("/api/admin/audit", requireAuth, requireOwner, async (req, res) => {
  const r = await pool.query("SELECT id,actor_email AS who,action,detail,created_at FROM audit_log ORDER BY created_at DESC LIMIT 100");
  res.json(r.rows);
});
app.get("/api/admin/failed", requireAuth, requireOwner, async (req, res) => {
  const r = await pool.query("SELECT id,source,note,created_at FROM failed_auth ORDER BY created_at DESC LIMIT 100");
  res.json(r.rows);
});
app.get("/api/admin/queue", requireAuth, requireOwner, async (req, res) => {
  const r = await pool.query("SELECT id,label,type,status,account_email AS account,updated_at FROM jobs ORDER BY created_at DESC LIMIT 100");
  res.json(r.rows);
});

// ─── admin write ops ─────────────────────────────────────────────────────────
app.post("/api/admin/unlock", async (req, res) => {
  const { code } = req.body || {};
  const h = req.headers.authorization || ""; const t = h.startsWith("Bearer ") ? h.slice(7) : null;
  let ownerViaToken = false;
  if (t) { try { const p = jwt.verify(t, JWT_SECRET); const r = await pool.query("SELECT email,role FROM accounts WHERE id=$1", [p.sub]); if (r.rows[0] && r.rows[0].role === "owner") ownerViaToken = true; } catch {} }
  if (code === ADMIN_CODE || ownerViaToken) return res.json({ ok: true });
  await logFailed("Admin unlock", "Invalid admin code", req.ip);
  res.status(401).json({ error: "Invalid code" });
});
app.post("/api/admin/announce", requireAuth, requireOwner, async (req, res) => {
  const { type, title, msg } = req.body || {};
  if (!title || !msg) return res.status(400).json({ error: "title and msg required" });
  const r = await pool.query("INSERT INTO announcements (type,title,msg) VALUES ($1,$2,$3) RETURNING id,type,title,msg,revoked,created_at", [type || "info", title, msg]);
  await audit(req.account.email, "Sent broadcast", title);
  res.json(r.rows[0]);
});
app.delete("/api/admin/announce/:id", requireAuth, requireOwner, async (req, res) => {
  await pool.query("UPDATE announcements SET revoked=TRUE WHERE id=$1", [req.params.id]);
  await audit(req.account.email, "Revoked broadcast", req.params.id);
  res.json({ ok: true });
});
app.patch("/api/admin/user/:id/status", requireAuth, requireOwner, async (req, res) => {
  const status = String((req.body || {}).status || "").toLowerCase();
  if (!["active", "suspended", "banned"].includes(status)) return res.status(400).json({ error: "invalid status" });
  const r = await pool.query("UPDATE accounts SET account_status=$1, token_revoked_at=CASE WHEN $1='active' THEN token_revoked_at ELSE NOW() END WHERE id=$2 RETURNING email,account_status", [status, req.params.id]);
  if (!r.rows[0]) return res.status(404).json({ error: "not found" });
  await audit(req.account.email, "Set account status → " + status, r.rows[0].email);
  res.json({ ok: true, status: r.rows[0].account_status, email: r.rows[0].email });
});
app.delete("/api/admin/user/:id", requireAuth, requireOwner, async (req, res) => {
  const e = await pool.query("SELECT email FROM accounts WHERE id=$1", [req.params.id]);
  await pool.query("DELETE FROM accounts WHERE id=$1", [req.params.id]);
  await audit(req.account.email, "Deleted account", e.rows[0] ? e.rows[0].email : req.params.id);
  res.json({ ok: true });
});
app.post("/api/admin/user/:id/reset-sessions", requireAuth, requireOwner, async (req, res) => {
  const e = await pool.query("UPDATE accounts SET token_revoked_at=NOW() WHERE id=$1 RETURNING email", [req.params.id]);
  await audit(req.account.email, "Forced session reset", e.rows[0] ? e.rows[0].email : req.params.id);
  res.json({ ok: true });
});
app.post("/api/admin/impersonate/:id", requireAuth, requireOwner, async (req, res) => {
  const u = await pool.query("SELECT name,email FROM accounts WHERE id=$1", [req.params.id]);
  if (!u.rows[0]) return res.status(404).json({ error: "not found" });
  const pc = await pool.query("SELECT COUNT(*)::int v FROM posts WHERE account_id=$1", [req.params.id]);
  const cc = await pool.query("SELECT COUNT(*)::int v FROM interactions WHERE account_id=$1 AND created_at >= NOW() - INTERVAL '7 days'", [req.params.id]);
  await audit(req.account.email, "Impersonated (view-as)", u.rows[0].email);
  res.json({ ok: true, summary: { name: u.rows[0].name, email: u.rows[0].email, posts: pc.rows[0].v, comments: cc.rows[0].v } });
});
app.post("/api/admin/queue/test", requireAuth, requireOwner, async (req, res) => {
  const r = await pool.query("INSERT INTO jobs (label,type,status,account_email) VALUES ($1,$2,$3,$4) RETURNING id,label,type,status,account_email AS account,updated_at", ["Diagnostic reply · @test_user", "Comment reply", "queued", req.account.email]);
  await audit(req.account.email, "Enqueued diagnostic job", r.rows[0].id);
  const id = r.rows[0].id;
  setTimeout(() => { pool.query("UPDATE jobs SET status='failed', updated_at=NOW() WHERE id=$1", [id]).catch(() => {}); }, 1500);
  res.json(r.rows[0]);
});
app.post("/api/admin/queue/:id/retry", requireAuth, requireOwner, async (req, res) => {
  await pool.query("UPDATE jobs SET status='processing', updated_at=NOW() WHERE id=$1", [req.params.id]);
  await audit(req.account.email, "Retried job", req.params.id);
  setTimeout(() => { pool.query("UPDATE jobs SET status='done', updated_at=NOW() WHERE id=$1", [req.params.id]).catch(() => {}); }, 1200);
  res.json({ ok: true });
});
app.delete("/api/admin/queue/:id", requireAuth, requireOwner, async (req, res) => {
  await pool.query("DELETE FROM jobs WHERE id=$1", [req.params.id]);
  await audit(req.account.email, "Cancelled job", req.params.id);
  res.json({ ok: true });
});

// ═══════════════════════════════════════════════════════════════════════════
//  COMMENT ENGINE — tags each interaction with account + post
// ═══════════════════════════════════════════════════════════════════════════
async function onNewComment({ accountId, postId, username, comment }) {
  let brandContext = "General business.", whatsapp = process.env.WHATSAPP_NUMBER || "";
  if (accountId) {
    const a = await pool.query("SELECT brand_context, whatsapp FROM accounts WHERE id=$1", [accountId]);
    if (a.rows[0]) { brandContext = a.rows[0].brand_context || brandContext; whatsapp = a.rows[0].whatsapp || whatsapp; }
  }
  const prev = process.env.WHATSAPP_NUMBER;
  process.env.WHATSAPP_NUMBER = whatsapp;
  try {
    const result = await processComment({ username, comment, brandContext });
    if (result.should_reply && postId) {
      await pool.query("UPDATE posts SET replies_count=replies_count+1, intent_count=intent_count+($1::bool)::int, comments_count=comments_count+1 WHERE id=$2", [result.intent === "high", postId]);
    }
    return result;
  } finally { process.env.WHATSAPP_NUMBER = prev; }
}
app.post("/test/comment", async (req, res) => {
  try {
    const { username, comment, brandContext, accountId, postId } = req.body || {};
    if (!username || !comment) return res.status(400).json({ error: "Need username and comment" });
    const result = accountId
      ? await onNewComment({ accountId, postId, username, comment })
      : await processComment({ username, comment, brandContext: brandContext || "Kenyan streetwear brand." });
    res.json({ success: true, result });
  } catch (e) { console.error("test", e); res.status(500).json({ error: e.message }); }
});
app.post("/webhook/tiktok", async (req, res) => {
  try {
    const { username, comment, brandContext, accountId, postId } = req.body || {};
    if (!username || !comment) return res.status(400).json({ error: "Missing fields" });
    const result = accountId
      ? await onNewComment({ accountId, postId, username, comment })
      : await processComment({ username, comment, brandContext });
    res.json({ success: true, result });
  } catch (e) { console.error("webhook", e); res.status(500).json({ error: e.message }); }
});

// ─── start ───────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  console.log("\n🧠 JibuFlow running on port " + PORT);
  await ensureSchema();
  await ensureOwner();
  try { await pool.query("SELECT 1"); console.log("✅ PostgreSQL connected"); }
  catch (e) { console.error("❌ DB connection FAILED:", e.message); }
  try {
    const ngrok = require("@ngrok/ngrok");
    const listener = await ngrok.forward({ addr: PORT, authtoken: process.env.NGROK_AUTHTOKEN });
    console.log("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console.log("✅ Public URL:  " + listener.url());
    console.log("📡 Webhook:    " + listener.url() + "/webhook/tiktok");
    console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
  } catch (e) { console.log("⚠️  ngrok skipped:", e.message); }
});
process.stdin.resume();