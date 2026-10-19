// Monitor Saham Syariah - server untuk Vercel (login, admin, data live).
// Didisain oleh @letsgobram - @motivaseein
import crypto from "node:crypto";
import { PAGE_B64 } from "./page.mjs";


/* ------------------------------------------------------------------ settings */
const env = (k, d) => process.env[k] ?? d;
const DEFAULT_ADMIN = () => env("MSS_ADMIN_USER", "AdminCoba1");
const DEFAULT_ADMIN_PW = () => env("MSS_ADMIN_PASSWORD", "Trial1!");
const SESSION_HOURS = () => parseFloat(env("MSS_SESSION_HOURS", "12"));
const COOKIE = "mss_sess";
const USER_RE = /^[A-Za-z0-9._-]{3,32}$/;
const PBKDF_ITER = 120000;
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36";
const SYM_RE = /^[A-Z0-9^=.\-]{1,15}$/;

/* ------------------------------------------------------------------ storage (Vercel Blob, private) */
// Setiap kunci disimpan sebagai file JSON privat: monitor-saham/<kunci>.json
const BLOB_DIR = "monitor-saham/";
let _blob = null;
async function blobLib() { try { if (!_blob) _blob = await import("@vercel/blob"); return _blob; } catch (e) { throw blobErr(e); } }
const blobErr = (e) => new Error(/credential|token|store/i.test(String(e && e.message))
  ? "Penyimpanan belum terhubung. Di Vercel buka Storage > Create > Blob (akses Private), hubungkan ke proyek ini, lalu Redeploy."
  : "Penyimpanan Vercel Blob gagal: " + String(e && e.message).slice(0, 160));
// Cache di memori agar kuota gratis Blob (operasi baca) tidak cepat habis:
// kunci akun dibaca ulang paling sering tiap 5 menit per instance; tulisan sendiri langsung memperbarui cache.
const MEM = new Map();
const TTL = { secret: Infinity, users: 300e3, des: 300e3 };
async function sget(k) {
  const ttl = TTL[k] || 0, c = MEM.get(k);
  if (ttl && c && Date.now() - c.t < ttl) return c.v == null ? null : JSON.parse(c.v);
  let v;
  if (globalThis.__MSS_TEST_STORE) v = await globalThis.__MSS_TEST_STORE.get(k);
  else {
    const { get } = await blobLib();
    let r;
    try { r = await get(BLOB_DIR + k + ".json", { access: "private", useCache: false }); } catch (e) { throw blobErr(e); }
    v = null;
    if (r && r.statusCode === 200 && r.stream) { try { v = JSON.parse(await new Response(r.stream).text()); } catch { v = null; } }
  }
  if (ttl) MEM.set(k, { t: Date.now(), v: v == null ? null : JSON.stringify(v) });
  return v;
}
async function sset(k, v) {
  if (globalThis.__MSS_TEST_STORE) await globalThis.__MSS_TEST_STORE.setJSON(k, v);
  else {
    const { put } = await blobLib();
    try { await put(BLOB_DIR + k + ".json", JSON.stringify(v), { access: "private", allowOverwrite: true, addRandomSuffix: false, contentType: "application/json", cacheControlMaxAge: 60 }); }
    catch (e) { throw blobErr(e); }
  }
  if (TTL[k]) MEM.set(k, { t: Date.now(), v: JSON.stringify(v) });
}

async function secret() {
  const fromEnv = env("MSS_SECRET", "");
  if (fromEnv && fromEnv.length >= 16) return fromEnv;
  let s = await sget("secret");
  if (!s || !s.v) { s = { v: crypto.randomBytes(32).toString("hex") }; await sset("secret", s); }
  return s.v;
}

function hashPw(pw, salt) {
  salt = salt || crypto.randomBytes(16).toString("hex");
  const dk = crypto.pbkdf2Sync(pw, Buffer.from(salt, "hex"), PBKDF_ITER, 32, "sha256").toString("hex");
  return `pbkdf2_sha256$${PBKDF_ITER}$${salt}$${dk}`;
}
function checkPw(pw, stored) {
  try {
    const [, it, salt, h] = stored.split("$");
    const dk = crypto.pbkdf2Sync(pw, Buffer.from(salt, "hex"), parseInt(it, 10), 32, "sha256");
    const hb = Buffer.from(h, "hex");
    return hb.length === dk.length && crypto.timingSafeEqual(dk, hb);
  } catch { return false; }
}

async function loadUsers() {
  let u = await sget("users");
  if (!u) {
    const name = DEFAULT_ADMIN();
    u = { [name.toLowerCase()]: { username: name, name: "Administrator", role: "admin", pw: hashPw(DEFAULT_ADMIN_PW()),
      must_change: true, active: true, expires: "", created: now(), last_login: null, ver: 1 } };
    await sset("users", u);
    await audit("system", "membuat akun admin awal " + name);
  }
  return u;
}
const saveUsers = (u) => sset("users", u);
const now = () => Math.floor(Date.now() / 1000);
const todayWIB = () => new Date(Date.now() + 7 * 3600e3).toISOString().slice(0, 10);
const stampWIB = () => new Date(Date.now() + 7 * 3600e3).toISOString().replace("T", " ").slice(0, 19);

async function audit(actor, msg) {
  try {
    const a = (await sget("audit")) || [];
    a.push(`${stampWIB()}\t${actor}\t${msg}`);
    await sset("audit", a.slice(-500));
  } catch {}
}

const publicUser = (u) => Object.fromEntries(["username", "name", "role", "must_change", "active", "expires", "created", "last_login"].map((k) => [k, u[k] ?? null]));
const expired = (u) => !!u.expires && todayWIB() > u.expires;
function pwPolicy(pw) {
  if (pw.length < 8) return "Password minimal 8 karakter.";
  if (!/[A-Za-z]/.test(pw) || !/\d/.test(pw)) return "Password harus berisi huruf dan angka.";
  if (pw.length > 128) return "Password terlalu panjang.";
  return null;
}

/* ------------------------------------------------------------------ sessions (signed) */
const b64u = (s) => Buffer.from(s).toString("base64url");
async function makeToken(u) {
  const exp = Math.floor(Date.now() / 1000 + SESSION_HOURS() * 3600);
  const payload = `${u.username.toLowerCase()}|${exp}|${u.ver || 1}`;
  const sig = crypto.createHmac("sha256", await secret()).update(payload).digest("hex");
  return b64u(`${payload}|${sig}`);
}
async function readToken(tok) {
  try {
    if (!tok) return null;
    const raw = Buffer.from(tok, "base64url").toString();
    const i = raw.lastIndexOf("|");
    const payload = raw.slice(0, i), sig = raw.slice(i + 1);
    const good = crypto.createHmac("sha256", await secret()).update(payload).digest("hex");
    if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
    const [key, exp, ver] = payload.split("|");
    if (parseInt(exp, 10) < Date.now() / 1000) return null;
    const u = (await loadUsers())[key];
    if (!u || !u.active || String(u.ver || 1) !== ver || expired(u)) return null;
    return u;
  } catch { return null; }
}

/* ------------------------------------------------------------------ login throttling (persisted) */
const WINDOW = 15 * 60;
async function fails(key) { const f = (await sget("fails")) || {}; return (f[key] || []).filter((t) => now() - t < WINDOW); }
async function noteFail(keys) {
  const f = (await sget("fails")) || {};
  for (const k of keys) f[k] = [...(f[k] || []).filter((t) => now() - t < WINDOW), now()];
  for (const k of Object.keys(f)) if (!f[k].some((t) => now() - t < WINDOW)) delete f[k];
  await sset("fails", f);
}
async function clearFail(key) { const f = (await sget("fails")) || {}; if (f[key]) { delete f[key]; await sset("fails", f); } }

/* ------------------------------------------------------------------ http helpers */
const SEC = { "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()", "Strict-Transport-Security": "max-age=31536000" };
function json(status, obj, extra = {}) {
  const h = new Headers({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...SEC });
  for (const [k, v] of Object.entries(extra)) { if (Array.isArray(v)) v.forEach((x) => h.append(k, x)); else h.set(k, v); }
  return new Response(JSON.stringify(obj), { status, headers: h });
}
const sessCookie = (v, age) => `${COOKIE}=${v}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${age}`;
const userCookie = (n, age) => `mss_user=${encodeURIComponent(n)}; Path=/; Secure; SameSite=Strict; Max-Age=${age}`;
function cookies(req) {
  const o = {};
  (req.headers.get("cookie") || "").split(";").forEach((p) => { const i = p.indexOf("="); if (i > 0) o[p.slice(0, i).trim()] = p.slice(i + 1).trim(); });
  return o;
}
const redirect = (loc) => new Response(null, { status: 302, headers: { Location: loc, ...SEC } });
function page() {
  return new Response(Buffer.from(PAGE_B64, "base64"), { status: 200, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", ...SEC } });
}
async function body(req) { try { const t = await req.text(); return t ? JSON.parse(t.slice(0, 1_000_000)) : {}; } catch { return {}; } }
const clientIP = (req, ctx) => ctx?.ip || (req.headers.get("x-real-ip") || req.headers.get("x-forwarded-for") || "?").split(",")[0].trim();

/* ------------------------------------------------------------------ main handler */
export const handle = async (req, context) => {
  const url = new URL(req.url, "https://" + (req.headers.get("host") || "localhost"));
  // vercel.json meneruskan path asli lewat ?__path=...
  const forced = url.searchParams.get("__path");
  url.searchParams.delete("__path");
  const path = decodeURIComponent(forced || url.pathname);
  const method = req.method.toUpperCase();
  try {
    if (method === "POST" && req.headers.get("x-requested-with") !== "mss") return json(403, { error: "permintaan ditolak" });
    if (path === "/auth/login" && method === "POST") return await login(req, context);

    const user = await readToken(cookies(req)[COOKIE]);
    if (path === "/auth/logout") {
      if (user) await audit(user.username, "keluar");
      return json(200, { ok: true }, { "Set-Cookie": [sessCookie("", 0), userCookie("", 0)] });
    }
    if (!user) {
      if (path === "/" || path === "/index.html") return redirect("/login");
      return json(401, { error: "silakan login", login: true });
    }
    if (user.must_change && (path.startsWith("/api/") || path.startsWith("/admin/"))) return json(403, { error: "ganti password terlebih dahulu", mustChange: true });

    if (path === "/" || path === "/index.html") return page();
    if (path === "/auth/me") return json(200, { user: publicUser(user) });
    if (path === "/auth/password" && method === "POST") return await changePassword(req, user);
    if (path.startsWith("/admin/")) {
      if (user.role !== "admin") { await audit(user.username, "DITOLAK akses admin " + path); return json(403, { error: "khusus admin" }); }
      return await admin(req, path, method, user);
    }
    if (path === "/api/des/state") {
      if (method === "POST") {
        if (user.role !== "admin") return json(403, { error: "khusus admin" });
        const b = await body(req);
        const codes = [...new Set((b.codes || []).filter((c) => typeof c === "string" && /^[A-Z]{4}$/.test(c)))].sort();
        if (codes.length < 150) return json(400, { error: "daftar terlalu pendek" });
        const doc = Object.fromEntries(["period", "kep", "eff", "src"].map((k) => [k, String(b[k] || "").slice(0, 200)]));
        Object.assign(doc, { codes, at: todayWIB(), by: user.username, partial: false });
        await sset("des", doc);
        await audit(user.username, `memperbarui DES ${doc.period} (${codes.length} saham)`);
        return json(200, { ok: true });
      }
      return json(200, (await sget("des")) || {});
    }
    if (path === "/api/des") {
      if (user.role !== "admin") return json(403, { error: "khusus admin" });
      try {
        const d = await cached("des", 6 * 3600, fetchDes);
        return new Response(d.data, { status: 200, headers: { "Content-Type": "application/pdf", "Cache-Control": "no-store", "X-DES-Url": encodeURIComponent(d.url), "X-DES-Title": encodeURIComponent(d.title.slice(0, 200)), ...SEC } });
      } catch (e) { return json(502, { error: "DES otomatis gagal: " + String(e.message || e).slice(0, 160) }); }
    }
    if (path.startsWith("/api/")) {
      try { return json(200, await api(path, url.searchParams)); }
      catch (e) {
        if (e.code === 404) return json(404, { error: "endpoint tidak dikenal" });
        if (e.code === 400) return json(400, { error: e.message });
        return json(502, { error: "gagal mengambil data: " + String(e.message || e).slice(0, 160) });
      }
    }
    return json(404, { error: "tidak ditemukan" });
  } catch (e) {
    console.error(e);
    const m = String(e && e.message || "");
    return json(500, { error: m.startsWith("Penyimpanan") ? m : "terjadi kesalahan di server" });
  }
};

async function login(req, context) {
  const b = await body(req);
  const uname = String(b.username || "").trim(), pw = String(b.password || "");
  const ip = clientIP(req, context);
  const key = `${ip}|${uname.toLowerCase()}`;
  if ((await fails(key)).length >= 5 || (await fails(ip + "|*")).length >= 25)
    return json(429, { error: "Terlalu banyak percobaan gagal. Coba lagi 15 menit lagi." });
  const users = await loadUsers();
  const u = users[uname.toLowerCase()];
  if (!u || !checkPw(pw, u.pw)) {
    await noteFail([key, ip + "|*"]);
    await audit(uname || "?", "login gagal dari " + ip);
    await new Promise((r) => setTimeout(r, 400));
    return json(401, { error: "Username atau password salah." });
  }
  if (!u.active) return json(403, { error: "Akun Anda dinonaktifkan. Hubungi admin." });
  if (expired(u)) return json(403, { error: `Masa akses Anda berakhir pada ${u.expires}. Hubungi admin.` });
  await clearFail(key);
  u.last_login = now();
  await saveUsers(users);
  await audit(u.username, "login dari " + ip);
  const age = Math.floor(SESSION_HOURS() * 3600);
  return json(200, { ok: true, user: publicUser(u) }, { "Set-Cookie": [sessCookie(await makeToken(u), age), userCookie(u.username, age)] });
}

async function changePassword(req, user) {
  const b = await body(req);
  const old = String(b.old || ""), nw = String(b.new || "");
  const users = await loadUsers();
  const u = users[user.username.toLowerCase()];
  if (!checkPw(old, u.pw)) return json(400, { error: "Password lama salah." });
  const err = pwPolicy(nw);
  if (err) return json(400, { error: err });
  if (checkPw(nw, u.pw)) return json(400, { error: "Password baru harus berbeda dari password lama." });
  u.pw = hashPw(nw); u.must_change = false; u.ver = (u.ver || 1) + 1;
  await saveUsers(users);
  await audit(u.username, "mengganti password");
  const age = Math.floor(SESSION_HOURS() * 3600);
  return json(200, { ok: true, user: publicUser(u) }, { "Set-Cookie": [sessCookie(await makeToken(u), age), userCookie(u.username, age)] });
}

async function admin(req, path, method, me) {
  const users = await loadUsers();
  if (path === "/admin/users" && method === "GET") {
    const lst = Object.values(users).map(publicUser).sort((a, b) => (a.role !== "admin") - (b.role !== "admin") || a.username.toLowerCase().localeCompare(b.username.toLowerCase()));
    return json(200, { users: lst });
  }
  if (path === "/admin/audit" && method === "GET") return json(200, { lines: ((await sget("audit")) || []).slice(-200).reverse() });
  if (path === "/admin/users" && method === "POST") {
    const b = await body(req);
    const uname = String(b.username || "").trim(), name = String(b.name || "").trim().slice(0, 80), pw = String(b.password || "");
    const role = b.role === "admin" ? "admin" : "user", exp = String(b.expires || "").trim();
    if (!USER_RE.test(uname)) return json(400, { error: "Username 3–32 karakter: huruf, angka, titik, garis bawah atau tanda hubung." });
    if (users[uname.toLowerCase()]) return json(400, { error: "Username sudah dipakai." });
    if (!name) return json(400, { error: "Nama wajib diisi." });
    const err = pwPolicy(pw); if (err) return json(400, { error: err });
    if (exp && !/^20\d\d-\d\d-\d\d$/.test(exp)) return json(400, { error: "Format tanggal berlaku: YYYY-MM-DD." });
    users[uname.toLowerCase()] = { username: uname, name, role, pw: hashPw(pw), must_change: b.must_change !== false, active: true,
      expires: exp, created: now(), last_login: null, ver: 1, created_by: me.username };
    await saveUsers(users);
    await audit(me.username, `membuat akun ${uname} (${role})`);
    return json(200, { ok: true, user: publicUser(users[uname.toLowerCase()]) });
  }
  const m = path.match(/^\/admin\/users\/([A-Za-z0-9._-]{3,32})$/);
  if (m && method === "POST") {
    const key = m[1].toLowerCase(), u = users[key];
    if (!u) return json(404, { error: "Pengguna tidak ditemukan." });
    const b = await body(req), act = b.action, isSelf = key === me.username.toLowerCase();
    const activeAdmins = Object.values(users).filter((x) => x.role === "admin" && x.active);
    if (["disable", "delete", "demote"].includes(act) && u.role === "admin" && u.active && activeAdmins.length <= 1)
      return json(400, { error: "Harus ada minimal satu admin aktif." });
    if (["disable", "delete"].includes(act) && isSelf) return json(400, { error: "Anda tidak bisa menonaktifkan atau menghapus akun sendiri." });
    let msg;
    if (act === "reset") {
      const pw = String(b.password || ""); const err = pwPolicy(pw); if (err) return json(400, { error: err });
      u.pw = hashPw(pw); u.must_change = b.must_change !== false; u.ver = (u.ver || 1) + 1; msg = "reset password";
    } else if (act === "disable") { u.active = false; u.ver = (u.ver || 1) + 1; msg = "menonaktifkan"; }
    else if (act === "enable") { u.active = true; msg = "mengaktifkan"; }
    else if (act === "promote" || act === "demote") { u.role = act === "promote" ? "admin" : "user"; u.ver = (u.ver || 1) + 1; msg = "mengubah peran jadi " + u.role; }
    else if (act === "expires") {
      const exp = String(b.expires || "").trim();
      if (exp && !/^20\d\d-\d\d-\d\d$/.test(exp)) return json(400, { error: "Format tanggal berlaku: YYYY-MM-DD." });
      u.expires = exp; msg = "mengatur masa berlaku " + (exp || "tanpa batas");
    } else if (act === "rename") {
      const nm = String(b.name || "").trim().slice(0, 80); if (!nm) return json(400, { error: "Nama wajib diisi." });
      u.name = nm; msg = "mengubah nama";
    } else if (act === "delete") {
      delete users[key]; await saveUsers(users); await audit(me.username, "menghapus akun " + m[1]); return json(200, { ok: true });
    } else return json(400, { error: "aksi tidak dikenal" });
    await saveUsers(users);
    await audit(me.username, `${msg} akun ${u.username}`);
    return json(200, { ok: true, user: publicUser(u) });
  }
  return json(404, { error: "tidak ditemukan" });
}

/* ------------------------------------------------------------------ live data */
const CACHE = new Map();
async function cached(key, ttl, fn) {
  const hit = CACHE.get(key);
  if (hit && Date.now() / 1000 - hit[0] < ttl) return hit[1];
  const v = await fn();
  CACHE.set(key, [Date.now() / 1000, v]);
  if (CACHE.size > 600) CACHE.delete(CACHE.keys().next().value);
  return v;
}
const ysym = (s) => (s.startsWith("^") || s.includes("=") || s.includes(".") ? s : s + ".JK");
const YC = { cookie: "", crumb: "", t: 0 };

async function get(url, { accept = "application/json,text/plain,*/*", timeout = 9000, cookie = "" } = {}) {
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const h = { "User-Agent": UA, Accept: accept, "Accept-Language": "id-ID,id;q=0.9,en;q=0.8" };
    if (cookie) h.Cookie = cookie;
    const r = await fetch(url, { headers: h, signal: ctl.signal, redirect: "follow" });
    return r;
  } finally { clearTimeout(t); }
}
async function getJSON(url, opts) {
  const r = await get(url, opts);
  if (!r.ok) { const e = new Error("HTTP " + r.status); e.status = r.status; throw e; }
  return r.json();
}
async function crumb(force) {
  if (YC.crumb && !force && Date.now() - YC.t < 3600e3) return YC;
  try {
    const r = await get("https://fc.yahoo.com", { accept: "text/html" });
    const sc = typeof r.headers.getSetCookie === "function" ? r.headers.getSetCookie() : [r.headers.get("set-cookie") || ""];
    YC.cookie = sc.map((c) => c.split(";")[0]).filter(Boolean).join("; ");
  } catch {}
  for (const host of ["query1", "query2"]) {
    try {
      const r = await get(`https://${host}.finance.yahoo.com/v1/test/getcrumb`, { cookie: YC.cookie });
      const c = (await r.text()).trim();
      if (r.ok && c && !c.includes("<") && c.length < 40) { YC.crumb = c; YC.t = Date.now(); return YC; }
    } catch {}
  }
  return YC;
}

async function fetchChart(sym, range, interval) {
  let last;
  for (const host of ["query1", "query2"]) {
    try {
      const j = await getJSON(`https://${host}.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(ysym(sym))}?range=${range}&interval=${interval}&includePrePost=false`);
      const res = j.chart.result[0], q = res.indicators.quote[0], m = res.meta;
      const rows = [];
      (res.timestamp || []).forEach((t, i) => { if (q.close[i] != null && q.open[i] != null) rows.push([t, q.open[i], q.high[i], q.low[i], q.close[i], q.volume[i] || 0]); });
      return { s: sym, meta: { price: m.regularMarketPrice ?? null, prev: m.chartPreviousClose ?? m.previousClose ?? null, h52: m.fiftyTwoWeekHigh ?? null, l52: m.fiftyTwoWeekLow ?? null,
        dayHigh: m.regularMarketDayHigh ?? null, dayLow: m.regularMarketDayLow ?? null, vol: m.regularMarketVolume ?? null, time: m.regularMarketTime ?? null,
        name: m.longName || m.shortName || null, cur: m.currency ?? null }, rows };
    } catch (e) { last = e; }
  }
  throw last || new Error("chart gagal");
}
async function fetchDiv(sym) {
  let last;
  for (const host of ["query1", "query2"]) {
    try {
      const j = await getJSON(`https://${host}.finance.yahoo.com/v8/finance/chart/${encodeURIComponent(ysym(sym))}?range=10y&interval=1mo&events=div`);
      const res = j.chart.result[0];
      const items = Object.values((res.events && res.events.dividends) || {}).filter((d) => d && d.date && d.amount)
        .map((d) => ({ t: Math.trunc(d.date), a: Number(d.amount) })).sort((a, b) => a.t - b.t);
      return { s: sym, items, cur: (res.meta && res.meta.currency) || null, at: Math.trunc(Date.now() / 1000) };
    } catch (e) { last = e; }
  }
  throw last || new Error("dividen gagal");
}
const raw = (x) => (x && typeof x === "object" ? x.raw ?? null : x ?? null);

async function fetchSummary(sym) {
  const mods = "price,summaryDetail,defaultKeyStatistics,financialData,assetProfile,calendarEvents,recommendationTrend";
  for (let attempt = 0; attempt < 2; attempt++) {
    const c = await crumb(attempt === 1);
    try {
      const j = await getJSON(`https://query1.finance.yahoo.com/v10/finance/quoteSummary/${encodeURIComponent(ysym(sym))}?modules=${mods}${c.crumb ? "&crumb=" + encodeURIComponent(c.crumb) : ""}`, { cookie: c.cookie });
      return j.quoteSummary.result[0];
    } catch (e) { if (!(e.status === 401 || e.status === 403) || attempt === 1) throw e; }
  }
}
const TS_TYPES = ["quarterlyTotalRevenue", "quarterlyNetIncome", "quarterlyTotalDebt", "quarterlyStockholdersEquity", "quarterlyOperatingCashFlow",
  "quarterlyInvestingCashFlow", "quarterlyFinancingCashFlow", "quarterlyFreeCashFlow", "quarterlyCapitalExpenditure", "quarterlyTotalAssets",
  "annualTotalRevenue", "annualNetIncome", "annualOperatingCashFlow", "annualInvestingCashFlow", "annualFinancingCashFlow", "annualFreeCashFlow",
  "annualCapitalExpenditure", "annualBasicEPS", "annualDilutedEPS"];
async function fetchTimeseries(sym) {
  const p2 = now() + 86400, p1 = p2 - 86400 * 365 * 4, out = {};
  try {
    const j = await getJSON(`https://query1.finance.yahoo.com/ws/fundamentals-timeseries/v1/finance/timeseries/${encodeURIComponent(ysym(sym))}?type=${TS_TYPES.join(",")}&period1=${p1}&period2=${p2}`);
    for (const r of j?.timeseries?.result || []) {
      const typ = (r?.meta?.type || [])[0];
      if (!typ || !r[typ]) continue;
      out[typ] = r[typ].filter(Boolean).map((v) => ({ d: v.asOfDate, v: raw(v.reportedValue), c: v.currencyCode })).filter((x) => x.v != null).sort((a, b) => (a.d || "").localeCompare(b.d || ""));
    }
  } catch (e) { out._err = String(e.message).slice(0, 120); }
  return out;
}
async function fundamentals(sym) {
  let R = {}, err = null;
  const [s, ts] = await Promise.allSettled([fetchSummary(sym), fetchTimeseries(sym)]);
  if (s.status === "fulfilled") R = s.value || {}; else err = String(s.reason?.message || s.reason).slice(0, 160);
  const pr = R.price || {}, sd = R.summaryDetail || {}, ks = R.defaultKeyStatistics || {}, fd = R.financialData || {}, ap = R.assetProfile || {}, ce = R.calendarEvents || {};
  const fcur = fd.financialCurrency || "IDR", usd = fcur !== "IDR";
  let pbv = raw(ks.priceToBook); if (pbv != null && pbv > 50) pbv = null;
  const der = raw(fd.debtToEquity);
  const f = { name: pr.longName || pr.shortName || sym, sector: ap.sector || "", ind: ap.industry || "", mcap: raw(pr.marketCap),
    pe: raw(sd.trailingPE), fpe: raw(sd.forwardPE), pbv, roe: raw(fd.returnOnEquity), roa: raw(fd.returnOnAssets), der: der != null ? der / 100 : null,
    dy: raw(sd.dividendYield), dps: usd ? null : raw(sd.trailingAnnualDividendRate), payout: raw(sd.payoutRatio),
    revg: raw(fd.revenueGrowth), epsg: raw(fd.earningsGrowth), npm: raw(fd.profitMargins), cr: raw(fd.currentRatio),
    eps: usd ? null : raw(ks.trailingEps), bv: usd ? null : raw(ks.bookValue), exd: sd.exDividendDate?.fmt || null,
    rec: fd.recommendationKey || "", tgt: raw(fd.targetMeanPrice), nan: raw(fd.numberOfAnalystOpinions),
    earn: ce.earnings?.earningsDate?.[0]?.fmt || null, usd, fcur, summary: (ap.longBusinessSummary || "").slice(0, 600) };
  return { s: sym, f, ts: ts.status === "fulfilled" ? ts.value : {}, err, at: now() };
}

const decodeXml = (s) => s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&amp;/g, "&").trim();
async function fetchNews(sym, name) {
  let terms = `"${sym}" saham`;
  if (name) {
    const short = name.replace(/\b(PT|Tbk|Persero|Perusahaan Perseroan)\b\.?/gi, "").replace(/[().,]/g, " ").split(/\s+/).filter(Boolean);
    if (short.length) terms = `("${sym}" OR "${short.slice(0, 3).join(" ")}") saham`;
  }
  const r = await get(`https://news.google.com/rss/search?q=${encodeURIComponent(terms + " when:30d")}&hl=id&gl=ID&ceid=ID:id`, { accept: "application/rss+xml,application/xml,text/xml" });
  if (!r.ok) throw new Error("berita HTTP " + r.status);
  const xml = await r.text(), items = [];
  for (const m of xml.matchAll(/<item>([\s\S]*?)<\/item>/g)) {
    const it = m[1], tag = (t) => { const x = it.match(new RegExp(`<${t}[^>]*>([\\s\\S]*?)</${t}>`)); return x ? decodeXml(x[1]) : ""; };
    let title = tag("title"); const src = tag("source");
    if (src && title.endsWith(" - " + src)) title = title.slice(0, -(src.length + 3));
    const d = Date.parse(tag("pubDate"));
    items.push({ title, link: tag("link"), src, ts: isNaN(d) ? null : Math.floor(d / 1000) });
  }
  items.sort((a, b) => (b.ts || 0) - (a.ts || 0));
  return { s: sym, items: items.slice(0, 25), at: now() };
}

async function pool(items, n, fn) {
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k]); } }));
  return out;
}
async function api(path, qs) {
  const syms = () => {
    const out = (qs.get("s") || "").toUpperCase().split(",").filter((x) => x && SYM_RE.test(x));
    if (!out.length) { const e = new Error("parameter s kosong"); e.code = 400; throw e; }
    return out.slice(0, 60);
  };
  if (path === "/api/health") return { ok: true, time: now(), version: 2, host: "vercel" };
  if (path === "/api/quotes") {
    const items = await pool(syms(), 10, async (s) => {
      try { const d = await cached("q:" + s, 25, () => fetchChart(s, "1d", "5m")); return { s, meta: d.meta, open: d.rows[0]?.[1] ?? null, last: d.rows.at(-1) ?? null }; }
      catch (e) { return { s, err: String(e.message).slice(0, 120) }; }
    });
    return { items, at: now() };
  }
  if (path === "/api/history") {
    const s = syms()[0];
    return qs.get("tf") === "15m" ? cached("h15:" + s, 60, () => fetchChart(s, "5d", "15m")) : cached("hd:" + s, 300, () => fetchChart(s, "1y", "1d"));
  }
  if (path === "/api/fund") { const s = syms()[0]; return cached("f:" + s, 6 * 3600, () => fundamentals(s)); }
  if (path === "/api/div") { const s = syms()[0]; return cached("d:" + s, 12 * 3600, () => fetchDiv(s)); }
  if (path === "/api/news") { const s = syms()[0]; return cached("n:" + s, 1800, () => fetchNews(s, (qs.get("name") || "").slice(0, 80))); }
  const e = new Error("tidak dikenal"); e.code = 404; throw e;
}

/* ------------------------------------------------------------------ Daftar Efek Syariah (OJK) */
const DES_START = "https://www.ojk.go.id/id/kanal/syariah/data-dan-statistik/daftar-efek-syariah/Default.aspx";
function links(html, base) {
  const out = [];
  for (const m of html.matchAll(/<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi)) {
    try { out.push([new URL(m[1].trim(), base).href, m[2].replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim()]); } catch {}
  }
  return out;
}
function desScore(u, t) {
  const s = decodeURIComponent(u) + " " + t;
  const ys = (s.match(/20[2-4]\d/g) || []).map(Number);
  if (!ys.length) return null;
  const per = /periode[\s\-_]*ii\b|periode[\s\-_]*2\b|november|nopember/i.test(s) ? 2 : 1;
  return Math.max(...ys) * 10 + per * 2 + (/\bSK\b|DES|daftar[\s\-_]*efek/i.test(s) ? 1 : 0);
}
async function fetchDes() {
  const r = await get(DES_START, { accept: "text/html", timeout: 8000 });
  if (!r.ok) throw new Error("halaman DES OJK tidak dapat diakses");
  const html = await r.text();
  const pdfs = new Map(), pages = [];
  for (const [u, t] of links(html, DES_START)) {
    const lu = u.toLowerCase();
    if (lu.endsWith(".pdf") && (lu.includes("efek") || lu.includes("des") || /efek/i.test(t))) pdfs.set(u, t);
    else if (lu.includes("daftar-efek-syariah") && !lu.endsWith("default.aspx")) { const sc = desScore(u, t); if (sc) pages.push([sc, u, t]); }
  }
  pages.sort((a, b) => b[0] - a[0]);
  await Promise.all(pages.slice(0, 4).map(async ([, u, t]) => {
    try { const sub = await (await get(u, { accept: "text/html", timeout: 6000 })).text(); for (const [pu, pt] of links(sub, u)) if (pu.toLowerCase().endsWith(".pdf")) pdfs.set(pu, (pt + " " + t).trim()); } catch {}
  }));
  const ranked = [...pdfs.entries()].map(([u, t]) => [desScore(u, t) || 0, u, t]).sort((a, b) => b[0] - a[0]);
  if (!ranked.length) throw new Error("file PDF DES tidak ditemukan di situs OJK");
  const [, url, title] = ranked[0];
  const pr = await get(url, { accept: "application/pdf,*/*", timeout: 9000 });
  const data = new Uint8Array(await pr.arrayBuffer());
  if (String.fromCharCode(...data.slice(0, 4)) !== "%PDF") throw new Error("file yang diunduh bukan PDF");
  if (data.length > 5.5e6) throw new Error("file PDF terlalu besar untuk diambil otomatis; gunakan Impor file DES");
  return { url, title: title || decodeURIComponent(url.split("/").pop()), data };
}
