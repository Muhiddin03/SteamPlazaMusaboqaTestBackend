'use strict';
require('dotenv').config();

const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

// ─── CONFIG ────────────────────────────────────────────────────────────────────
const IS_PROD = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT) || 3000;
const JWT_SECRET = process.env.JWT_SECRET || '';
const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || 'admin').trim().toLowerCase();
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim().replace(/\/+$/, '')).filter(Boolean);

const TOKEN_TTL = '8h';
const BCRYPT_COST = 12;
const MAX_FAILED_LOGINS = 5;
const ANSWER_GRACE_MS = 3000;          // tarmoq kechikishi uchun qo'shimcha vaqt
const VIOLATION_DEDUP_MS = 4000;       // bitta harakat bir necha hodisa chiqarsa, 1 marta sanaladi
const ABANDON_AFTER_MIN = 5;           // shuncha daqiqa aloqa bo'lmasa test "tashlab ketilgan"
const SNAPSHOT_MAX_BYTES = 150 * 1024;
const LIVE_FRAME_TTL_MS = 60000;       // shundan eski jonli kadr ko'rsatilmaydi

// attempt_id -> { buf, at } — jonli kuzatuv uchun oxirgi kamera kadri (faqat xotirada)
const liveFrames = new Map();
// attempt_id -> vaqt: admin shu o'quvchini katta oynada kuzatmoqda (kadrlar tezroq so'raladi)
const watchedUntil = new Map();
const LIVE_FRAME_MS = 4000;
const WATCHED_FRAME_MS = 1000;

function fatal(msg) {
  console.error('❌ ' + msg);
  process.exit(1);
}
if (!process.env.DATABASE_URL) fatal('DATABASE_URL o\'rnatilmagan');
if (JWT_SECRET.length < 32) {
  fatal('JWT_SECRET kamida 32 ta belgi bo\'lishi kerak. Yaratish: ' +
    'node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))"');
}
if (!ALLOWED_ORIGINS.length) {
  console.warn('⚠️  ALLOWED_ORIGINS o\'rnatilmagan — API har qanday saytdan ochiq. Frontend manzilini kiriting.');
}

// ─── DATABASE ──────────────────────────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: IS_PROD ? { rejectUnauthorized: false } : false,
  max: 10
});
pool.on('error', err => console.error('PG pool xatosi:', err.message));

async function tx(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

async function initDB() {
  await tx(async db => {
    await db.query(`
      CREATE TABLE IF NOT EXISTS classes (
        id VARCHAR(50) PRIMARY KEY,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS tests (
        id SERIAL PRIMARY KEY,
        class_id VARCHAR(50) REFERENCES classes(id) ON DELETE CASCADE,
        question TEXT NOT NULL,
        correct_answer TEXT NOT NULL,
        options JSONB NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS tests_class_idx ON tests(class_id);

      CREATE TABLE IF NOT EXISTS admins (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        token_version INTEGER NOT NULL DEFAULT 0,
        failed_logins INTEGER NOT NULL DEFAULT 0,
        locked_until TIMESTAMPTZ,
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS settings (
        key VARCHAR(50) PRIMARY KEY,
        value JSONB NOT NULL
      );

      CREATE TABLE IF NOT EXISTS attempts (
        id SERIAL PRIMARY KEY,
        class_id VARCHAR(50) REFERENCES classes(id) ON DELETE CASCADE,
        student_name VARCHAR(100) NOT NULL,
        team_name VARCHAR(100) NOT NULL DEFAULT '',
        token_hash VARCHAR(80) UNIQUE NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'active',
        question_ids INTEGER[],
        current_index INTEGER NOT NULL DEFAULT 0,
        question_started_at TIMESTAMPTZ,
        score INTEGER NOT NULL DEFAULT 0,
        total INTEGER NOT NULL DEFAULT 0,
        violations INTEGER NOT NULL DEFAULT 0,
        last_violation_at TIMESTAMPTZ,
        camera BOOLEAN NOT NULL DEFAULT FALSE,
        ip VARCHAR(64),
        user_agent VARCHAR(300),
        started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_snapshot_at TIMESTAMPTZ,
        finished_at TIMESTAMPTZ
      );
      CREATE INDEX IF NOT EXISTS attempts_class_idx ON attempts(class_id, started_at DESC);
      CREATE INDEX IF NOT EXISTS attempts_status_idx ON attempts(status);

      -- Fanlar: savollar va urinishlar fan bo'yicha ajratiladi ('' — fansiz eski savollar)
      ALTER TABLE tests ADD COLUMN IF NOT EXISTS subject VARCHAR(60) NOT NULL DEFAULT '';
      ALTER TABLE tests ADD COLUMN IF NOT EXISTS qtype VARCHAR(10) NOT NULL DEFAULT 'choice';
      ALTER TABLE tests ADD COLUMN IF NOT EXISTS image_id INTEGER;
      ALTER TABLE tests ADD COLUMN IF NOT EXISTS sort_order INTEGER;
      CREATE INDEX IF NOT EXISTS tests_class_subject_idx ON tests(class_id, subject);
      ALTER TABLE attempts ADD COLUMN IF NOT EXISTS subject VARCHAR(60) NOT NULL DEFAULT '';

      -- Bitta o'quvchi har bir fandan bir marta topshiradi
      DROP INDEX IF EXISTS attempts_one_per_student;
      CREATE UNIQUE INDEX IF NOT EXISTS attempts_one_per_student_subject
        ON attempts(class_id, subject, lower(student_name), lower(team_name)) WHERE status <> 'legacy';

      -- Savol rasmlari (bir xil rasm bir marta saqlanadi)
      CREATE TABLE IF NOT EXISTS test_images (
        id SERIAL PRIMARY KEY,
        hash CHAR(64) UNIQUE NOT NULL,
        mime VARCHAR(40) NOT NULL,
        data BYTEA NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS attempt_answers (
        id SERIAL PRIMARY KEY,
        attempt_id INTEGER NOT NULL REFERENCES attempts(id) ON DELETE CASCADE,
        test_id INTEGER NOT NULL,
        question TEXT,
        correct_answer TEXT,
        answer TEXT,
        is_correct BOOLEAN NOT NULL DEFAULT FALSE,
        time_ms INTEGER,
        timed_out BOOLEAN NOT NULL DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE (attempt_id, test_id)
      );

      CREATE TABLE IF NOT EXISTS attempt_events (
        id SERIAL PRIMARY KEY,
        attempt_id INTEGER NOT NULL REFERENCES attempts(id) ON DELETE CASCADE,
        type VARCHAR(40) NOT NULL,
        detail VARCHAR(300),
        is_violation BOOLEAN NOT NULL DEFAULT FALSE,
        question_index INTEGER,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS attempt_events_idx ON attempt_events(attempt_id, created_at);
      -- Hodisa paytidagi kamera surati (dalil)
      ALTER TABLE attempt_events ADD COLUMN IF NOT EXISTS snapshot_id INTEGER;

      CREATE TABLE IF NOT EXISTS attempt_snapshots (
        id SERIAL PRIMARY KEY,
        attempt_id INTEGER NOT NULL REFERENCES attempts(id) ON DELETE CASCADE,
        image BYTEA NOT NULL,
        reason VARCHAR(40),
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS attempt_snapshots_idx ON attempt_snapshots(attempt_id, created_at);
    `);

    // Eski versiyadagi "results" jadvalidan natijalarni bir marta ko'chirib olamiz
    const legacy = await db.query(`SELECT to_regclass('public.results') AS t`);
    if (legacy.rows[0].t) {
      const done = await db.query(`SELECT 1 FROM settings WHERE key = 'legacy_migrated'`);
      if (!done.rowCount) {
        const r = await db.query(`
          INSERT INTO attempts (class_id, student_name, team_name, token_hash, status, score, total,
                                started_at, last_seen_at, finished_at)
          SELECT class_id, student_name, team_name, 'legacy-' || id, 'legacy', score, total,
                 created_at, created_at, created_at
          FROM results WHERE class_id IS NOT NULL`);
        await db.query(`INSERT INTO settings (key, value) VALUES ('legacy_migrated', 'true')`);
        console.log(`↪️  Eski natijalar ko'chirildi: ${r.rowCount} ta`);
      }
    }
  });
  console.log('✅ Database tables ready');
}

// ─── HELPERS ───────────────────────────────────────────────────────────────────
class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const asyncH = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');

// Bir qatorli matn: boshqaruv belgilari olib tashlanadi, bo'shliqlar yig'iladi
function cleanText(v, max) {
  if (typeof v !== 'string') return '';
  return v.replace(/[\u0000-\u001F\u007F]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}

// Ko'p qatorli matn (savollar uchun)
function cleanMultiline(v, max) {
  if (typeof v !== 'string') return '';
  return v.replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0009\u000B-\u001F\u007F]/g, ' ')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim().slice(0, max);
}

const CLASS_ID_RE = /^[\p{L}\p{N}][\p{L}\p{N} '’ʻʼ`._-]{0,49}$/u;

function parseId(v) {
  const n = Number(v);
  if (!Number.isSafeInteger(n) || n <= 0) throw new HttpError(400, 'Noto\'g\'ri ID');
  return n;
}

function shuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function uniqueOptions(raw) {
  let list = raw;
  if (typeof list === 'string') {
    try { list = JSON.parse(list); } catch { list = []; }
  }
  if (!Array.isArray(list)) return [];
  const seen = new Set();
  return list.filter(o => {
    if (typeof o !== 'string' || !o.trim() || seen.has(o)) return false;
    seen.add(o);
    return true;
  });
}

const COMMON_PASSWORDS = ['1234567890', 'qwertyuiop', 'password123', 'admin12345', 'parol12345', '1q2w3e4r5t'];

function passwordProblem(pw, username) {
  if (typeof pw !== 'string' || pw.length < 10) return 'Parol kamida 10 ta belgidan iborat bo\'lishi kerak';
  if (pw.length > 128) return 'Parol juda uzun (maks. 128)';
  if (!/\p{L}/u.test(pw) || !/\p{N}/u.test(pw)) return 'Parolda harf ham, raqam ham bo\'lishi kerak';
  if (username && pw.toLowerCase().includes(username.toLowerCase())) return 'Parolda login bo\'lmasligi kerak';
  if (COMMON_PASSWORDS.includes(pw.toLowerCase())) return 'Bu parol juda oddiy';
  return null;
}

// ─── SETTINGS ──────────────────────────────────────────────────────────────────
const DEFAULT_SETTINGS = Object.freeze({
  question_time_sec: 45,       // har bir savolga beriladigan vaqt
  max_violations: 3,           // shuncha qoidabuzarlikdan keyin test to'xtatiladi (0 = to'xtatilmaydi)
  questions_per_attempt: 0,    // har bir o'quvchiga nechta tasodifiy savol (0 = hammasi)
  camera_mode: 'required',     // 'off' | 'required'
  share_grade_tests: false,    // true: 7-A, 7-B ... barcha 7-sinf savollari aralash beriladi
  show_score_to_student: true, // test oxirida o'quvchiga ball ko'rsatiladi
  allow_paper: false           // qog'ozda ishlashga ruxsat (matematika): pastga qarash xavf hisoblanmaydi
});

function normalizeSettings(input, base) {
  const src = input && typeof input === 'object' ? input : {};
  const int = (key, min, max) => {
    const n = Number(src[key]);
    return Number.isInteger(n) && n >= min && n <= max ? n : base[key];
  };
  const bool = key => (typeof src[key] === 'boolean' ? src[key] : base[key]);
  return {
    question_time_sec: int('question_time_sec', 10, 600),
    max_violations: int('max_violations', 0, 50),
    questions_per_attempt: int('questions_per_attempt', 0, 500),
    camera_mode: ['off', 'required'].includes(src.camera_mode) ? src.camera_mode : base.camera_mode,
    share_grade_tests: bool('share_grade_tests'),
    show_score_to_student: bool('show_score_to_student'),
    allow_paper: bool('allow_paper')
  };
}

// Sozlamalar xotirada saqlanadi — har bir javobda bazaga murojaat qilinmaydi
let settingsCache = null;
let settingsCachedAt = 0;
const SETTINGS_TTL_MS = 30000;

async function getSettings() {
  if (settingsCache && Date.now() - settingsCachedAt < SETTINGS_TTL_MS) return settingsCache;
  const r = await pool.query(`SELECT value FROM settings WHERE key = 'app'`);
  settingsCache = normalizeSettings(r.rows[0]?.value, DEFAULT_SETTINGS);
  settingsCachedAt = Date.now();
  return settingsCache;
}

// ─── ADMIN AUTH ────────────────────────────────────────────────────────────────
// Mavjud bo'lmagan login uchun ham bcrypt ishlaydi — javob vaqti bir xil bo'ladi
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), BCRYPT_COST);

async function seedAdmin() {
  const envPw = process.env.ADMIN_PASSWORD || '';
  const { rows } = await pool.query('SELECT id FROM admins WHERE username = $1', [ADMIN_USERNAME]);

  if (!rows.length) {
    const { rows: [{ n }] } = await pool.query('SELECT count(*)::int AS n FROM admins');
    if (n > 0) return;
    const problem = passwordProblem(envPw, ADMIN_USERNAME);
    if (problem) fatal(`ADMIN_PASSWORD yaroqsiz: ${problem}`);
    await pool.query('INSERT INTO admins (username, password_hash) VALUES ($1, $2)',
      [ADMIN_USERNAME, await bcrypt.hash(envPw, BCRYPT_COST)]);
    console.log(`👤 Admin yaratildi: ${ADMIN_USERNAME}`);
    return;
  }

  if (process.env.ADMIN_RESET_PASSWORD === 'true') {
    const problem = passwordProblem(envPw, ADMIN_USERNAME);
    if (problem) fatal(`ADMIN_PASSWORD yaroqsiz: ${problem}`);
    await pool.query(`
      UPDATE admins SET password_hash = $2, token_version = token_version + 1,
             failed_logins = 0, locked_until = NULL, updated_at = NOW()
      WHERE id = $1`, [rows[0].id, await bcrypt.hash(envPw, BCRYPT_COST)]);
    console.warn('⚠️  Admin paroli ADMIN_PASSWORD ga tiklandi. ADMIN_RESET_PASSWORD ni o\'chirib qo\'ying!');
  }
}

function signAdmin(admin) {
  return jwt.sign({ ver: admin.token_version }, JWT_SECRET, {
    subject: String(admin.id), expiresIn: TOKEN_TTL, issuer: 'steam-plaza', audience: 'admin', algorithm: 'HS256'
  });
}

const requireAdmin = asyncH(async (req, res, next) => {
  const m = /^Bearer ([\w.-]+)$/.exec(req.get('authorization') || '');
  if (!m) throw new HttpError(401, 'Avtorizatsiya talab qilinadi');
  let payload;
  try {
    payload = jwt.verify(m[1], JWT_SECRET, { algorithms: ['HS256'], issuer: 'steam-plaza', audience: 'admin' });
  } catch {
    throw new HttpError(401, 'Sessiya tugagan, qaytadan kiring');
  }
  const { rows } = await pool.query('SELECT id, username, token_version FROM admins WHERE id = $1', [payload.sub]);
  if (!rows[0] || rows[0].token_version !== payload.ver) throw new HttpError(401, 'Sessiya tugagan, qaytadan kiring');
  req.admin = rows[0];
  next();
});

async function verifyAdminPassword(adminId, password) {
  const { rows } = await pool.query('SELECT password_hash FROM admins WHERE id = $1', [adminId]);
  const ok = typeof password === 'string' && rows[0] && await bcrypt.compare(password.slice(0, 128), rows[0].password_hash);
  if (!ok) throw new HttpError(403, 'Parol noto\'g\'ri');
}

// ─── ATTEMPT (TEST SESSIYASI) LOGIKASI ─────────────────────────────────────────
// Qoidabuzarlik — sanaladi va limitga yetsa test to'xtatiladi
const VIOLATION_TYPES = new Set([
  'tab_hidden', 'focus_lost', 'fullscreen_exit', 'split_screen', 'multi_tab', 'camera_off',
  'face_missing', 'multiple_faces', 'head_turned_long', 'looking_down_long'
]);
// Ogohlantirish — faqat yoziladi, admin ko'radi
const WARNING_TYPES = new Set([
  'window_blur', 'copy', 'paste', 'key_blocked', 'screenshot', 'offline', 'tab_return', 'camera_denied', 'devtools',
  'head_turned', 'looking_down', 'motion', 'ai_unavailable', 'face_away', 'multiple_faces_short'
]);
// Jonli kuzatuvda admin darhol ko'rishi kerak bo'lgan hodisalar
const ALERT_TYPES = [...VIOLATION_TYPES, 'head_turned', 'looking_down', 'motion', 'face_away', 'multiple_faces_short', 'copy', 'paste', 'screenshot', 'devtools', 'camera_denied'];

async function withAttempt(req, fn) {
  const token = req.get('x-attempt-token') || '';
  if (!token || token.length > 100) throw new HttpError(401, 'Test sessiyasi topilmadi');
  return tx(async db => {
    const { rows } = await db.query('SELECT * FROM attempts WHERE token_hash = $1 FOR UPDATE', [sha256(token)]);
    if (!rows[0]) throw new HttpError(404, 'Test sessiyasi topilmadi');
    return fn(db, rows[0]);
  });
}

async function logEvent(db, a, type, detail, isViolation, snapshotId = null) {
  await db.query(
    `INSERT INTO attempt_events (attempt_id, type, detail, is_violation, question_index, snapshot_id)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [a.id, type, detail || null, !!isViolation, a.current_index + 1, snapshotId]
  );
}

// ─── Yozma javobni tekshirish ───
// "10", "10 m/s", "10m/s", "10 м/с", "13,3" — son bir xil bo'lsa to'g'ri; o'quvchi birlik yozsa, u ham mos kelishi kerak.
const CYR_TO_LAT = { а: 'a', б: 'b', в: 'v', г: 'g', д: 'd', е: 'e', ж: 'j', з: 'z', и: 'i', й: 'y', к: 'k', л: 'l', м: 'm',
  н: 'n', о: 'o', п: 'p', р: 'r', с: 's', т: 't', у: 'u', ф: 'f', х: 'x', ц: 's', ч: 'ch', ш: 'sh', ы: 'i', э: 'e', ю: 'yu', я: 'ya', ў: 'o', қ: 'q', ғ: 'g', ҳ: 'h' };
const SUPERSCRIPT = { '⁰': '0', '¹': '1', '²': '2', '³': '3', '⁴': '4', '⁵': '5', '⁶': '6', '⁷': '7', '⁸': '8', '⁹': '9', '⁻': '-' };
const UNIT_WORDS = [
  [/kilometr(?:lar)?/g, 'km'], [/santimetr/g, 'cm'], [/sm(?=\b|$)/g, 'cm'], [/metr(?:lar)?/g, 'm'],
  [/sekund(?:lar)?|soniya|sek/g, 's'], [/minut|daqiqa/g, 'min'], [/km\/s(?:oat)?$/g, 'km/soat'],
  [/km\/h$/g, 'km/soat'], [/joul/g, 'j'], [/vatt/g, 'w'], [/nyuton/g, 'n'], [/amper/g, 'a'], [/volt/g, 'v'], [/om$/g, 'ω']
];

function normalizeAnswer(s) {
  let t = String(s ?? '').toLowerCase()
    .replace(/[‘’ʻʼ`´]/g, "'")
    .replace(/[Ѐ-ӿ]/g, ch => CYR_TO_LAT[ch] ?? ch)
    .replace(/[⁰¹²³⁴⁵⁶⁷⁸⁹⁻]/g, ch => SUPERSCRIPT[ch])
    .replace(/[·×]/g, '*')
    .replace(/(\d)\s+(?=\d{3}\b)/g, '$1')   // "42 000" -> "42000"
    .replace(/,/g, '.')
    .replace(/\s+/g, '');
  return t;
}

function splitNumber(s) {
  const t = normalizeAnswer(s);
  const m = /^[^\d-]*?(-?\d+(?:\.\d+)?)(?:\*10\^?(-?\d+))?(.*)$/.exec(t);
  if (!m) return null;
  let value = Number(m[1]);
  if (m[2] !== undefined) value *= 10 ** Number(m[2]);
  let unit = m[3].replace(/^[.:]+/, '').replace(/\(.*\)$/, '');
  for (const [re, rep] of UNIT_WORDS) unit = unit.replace(re, rep);
  return { value, unit };
}

function isOpenAnswerCorrect(answer, correct) {
  if (answer == null || !String(answer).trim()) return false;
  if (normalizeAnswer(answer) === normalizeAnswer(correct)) return true;
  const a = splitNumber(answer);
  const c = splitNumber(correct);
  if (!a || !c) return false;
  const tol = Math.max(Math.abs(c.value) * 0.005, 1e-9);   // yaxlitlash uchun 0.5% farq
  if (Math.abs(a.value - c.value) > tol) return false;
  return !a.unit || !c.unit || a.unit === c.unit;
}

function isAnswerCorrect(test, answer) {
  if (answer == null) return false;
  return test.qtype === 'open' ? isOpenAnswerCorrect(answer, test.correct_answer) : answer === test.correct_answer;
}

// Yozma javobli savolga 2 barobar ko'p vaqt (hisoblash va yozish uchun)
function questionLimitMs(s, test) {
  return s.question_time_sec * 1000 * (test && test.qtype === 'open' ? 2 : 1);
}

async function recordAnswer(db, a, test, answer, timeMs, timedOut) {
  const isCorrect = !timedOut && isAnswerCorrect(test, answer);
  await db.query(
    `INSERT INTO attempt_answers (attempt_id, test_id, question, correct_answer, answer, is_correct, time_ms, timed_out)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     ON CONFLICT (attempt_id, test_id) DO NOTHING`,
    [a.id, test.id, test.question, test.correct_answer, answer, isCorrect, Math.round(timeMs), timedOut]
  );
}

async function finishAttempt(db, a, status) {
  const { rows } = await db.query(
    'SELECT count(*) FILTER (WHERE is_correct)::int AS score FROM attempt_answers WHERE attempt_id = $1', [a.id]);
  a.status = status;
  a.score = rows[0].score;
  a.total = (a.question_ids || []).length;
  a.finished_at = new Date();
  await db.query('UPDATE attempts SET status = $2, score = $3, total = $4, finished_at = $5 WHERE id = $1',
    [a.id, a.status, a.score, a.total, a.finished_at]);
  liveFrames.delete(a.id);
}

// Vaqti o'tgan savollarni yopadi, o'chirilgan savollarni tashlab ketadi, oxirida testni yakunlaydi.
// Joriy savolni (bazadan o'qilgan qatorni) qaytaradi — qayta so'ralmasligi uchun.
async function syncAttempt(db, a, s) {
  if (a.status !== 'active') return null;
  for (;;) {
    const ids = a.question_ids || [];
    if (a.current_index >= ids.length) {
      await finishAttempt(db, a, 'finished');
      return null;
    }
    const { rows } = await db.query(
      'SELECT id, question, correct_answer, options, qtype, image_id FROM tests WHERE id = $1', [ids[a.current_index]]);
    if (!rows[0]) {
      ids.splice(a.current_index, 1);
      a.question_ids = ids;
      await db.query('UPDATE attempts SET question_ids = $2, total = $3 WHERE id = $1', [a.id, ids, ids.length]);
      continue;
    }
    const limitMs = questionLimitMs(s, rows[0]);
    const startedAt = new Date(a.question_started_at).getTime();
    if (Date.now() - startedAt <= limitMs + ANSWER_GRACE_MS) return rows[0];

    await recordAnswer(db, a, rows[0], null, limitMs, true);
    a.current_index += 1;
    a.question_started_at = new Date(startedAt + limitMs);
    await db.query('UPDATE attempts SET current_index = $2, question_started_at = $3 WHERE id = $1',
      [a.id, a.current_index, a.question_started_at]);
  }
}

// O'quvchiga yuboriladigan holat. To'g'ri javob HECH QACHON yuborilmaydi.
async function buildState(db, a, s, current) {
  const state = {
    status: a.status,
    violations: a.violations,
    max_violations: s.max_violations,
    total: (a.question_ids || []).length
  };
  if (a.status !== 'active') {
    if (s.show_score_to_student) state.score = a.score;
    return state;
  }
  const currentId = a.question_ids[a.current_index];
  const t = current && current.id === currentId
    ? current
    : (await db.query('SELECT id, question, options, qtype, image_id FROM tests WHERE id = $1', [currentId])).rows[0];
  const limitMs = questionLimitMs(s, t);
  const elapsed = Date.now() - new Date(a.question_started_at).getTime();
  state.subject = a.subject || '';
  state.question = {
    id: t.id,
    number: a.current_index + 1,
    text: t.question,
    type: t.qtype === 'open' ? 'open' : 'choice',
    image_id: t.image_id || null,
    options: t.qtype === 'open' ? [] : shuffle(uniqueOptions(t.options)),
    limit_ms: limitMs,
    remaining_ms: Math.max(0, limitMs - elapsed)
  };
  return state;
}

// Savollar: fayldan yuklangan to'plam (hammasida tartib raqami bor) — fayldagi tartibda,
// chunki keyingi savol oldingisiga tayanishi mumkin; qo'lda qo'shilganlar — aralash.
async function pickQuestions(classId, subject, s) {
  const grade = /^(\d{1,2})-/.exec(classId)?.[1];
  const shared = s.share_grade_tests && grade;
  const { rows } = await pool.query(
    `SELECT id, sort_order FROM tests WHERE ${shared ? 'class_id ~ $1' : 'class_id = $1'} AND subject = $2`,
    [shared ? `^${grade}-` : classId, subject]);
  let list = rows;
  if (list.length && list.every(r => r.sort_order != null)) list = list.sort((x, z) => x.sort_order - z.sort_order || x.id - z.id);
  else list = shuffle(list);
  if (s.questions_per_attempt > 0) list = list.slice(0, s.questions_per_attempt);
  return list.map(r => r.id);
}

function riskLevel(a, counts) {
  if (a.status === 'terminated') return 'high';
  const c = k => Number(counts?.[k] || 0);
  const warnings = c('window_blur') + c('copy') + c('paste') + c('key_blocked') + c('screenshot') + c('reload') + c('devtools');
  const posture = c('head_turned') + c('looking_down') + c('motion') + c('face_away') + c('multiple_faces_short');
  if (a.violations >= 2 || c('fast_answer') >= 5 || posture >= 6) return 'high';
  if (a.violations >= 1 || c('fast_answer') >= 2 || c('connection_gap') >= 1 || c('camera_denied') ||
      c('ai_unavailable') || warnings >= 3 || posture >= 2) return 'medium';
  return 'low';
}

// ─── APP ───────────────────────────────────────────────────────────────────────
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({
  origin(origin, cb) {
    if (!origin || !ALLOWED_ORIGINS.length || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    cb(null, false);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Attempt-Token'],
  maxAge: 600
}));
app.use(express.json({ limit: '2mb' }));
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

const limiter = (windowMs, limit, error) => rateLimit({
  windowMs, limit, standardHeaders: 'draft-7', legacyHeaders: false, message: { error }
});
// Bir maktab/sinf bitta IP orqali chiqishi mumkin, shuning uchun umumiy limit keng
app.use('/api/', limiter(60 * 1000, 4000, 'Juda ko\'p so\'rov. Biroz kuting.'));
const loginLimiter = limiter(15 * 60 * 1000, 10, 'Juda ko\'p urinish. 15 daqiqadan keyin qayta urinib ko\'ring.');
const startLimiter = limiter(10 * 60 * 1000, 120, 'Juda ko\'p urinish. Biroz kuting.');

// ─── HEALTH ────────────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'ok', message: 'Steam Plaza API ishlayapti!' }));

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC (O'QUVCHI) API
// ═══════════════════════════════════════════════════════════════════════════════

// Sinflar va ulardagi fanlar (savoli bor fanlar, nomi bo'yicha)
app.get('/api/classes', asyncH(async (req, res) => {
  const { rows } = await pool.query(`
    SELECT c.id,
           COALESCE((SELECT json_agg(json_build_object('subject', s.subject, 'count', s.n) ORDER BY s.subject)
                     FROM (SELECT subject, count(*)::int AS n FROM tests t WHERE t.class_id = c.id GROUP BY subject) s),
                    '[]'::json) AS subjects
    FROM classes c
    ORDER BY (substring(c.id from '^\\d+'))::int NULLS LAST, c.id`);
  res.json(rows);
}));

// Savol rasmi (test paytida o'quvchiga ko'rsatiladi)
app.get('/api/test-images/:id', asyncH(async (req, res) => {
  const { rows } = await pool.query('SELECT mime, data FROM test_images WHERE id = $1', [parseId(req.params.id)]);
  if (!rows[0]) throw new HttpError(404, 'Rasm topilmadi');
  res.set('Content-Type', rows[0].mime).set('Cache-Control', 'public, max-age=86400').send(rows[0].data);
}));

app.get('/api/settings', asyncH(async (req, res) => {
  const s = await getSettings();
  res.json({
    question_time_sec: s.question_time_sec,
    max_violations: s.max_violations,
    camera_mode: s.camera_mode,
    allow_paper: s.allow_paper
  });
}));

app.post('/api/attempt/start', startLimiter, asyncH(async (req, res) => {
  const classId = cleanText(req.body?.class_id, 50);
  const studentName = cleanText(req.body?.student_name, 100);
  const teamName = cleanText(req.body?.team_name, 100);
  if (!classId) throw new HttpError(400, 'Sinf tanlanmagan');
  if (studentName.length < 3) throw new HttpError(400, 'Ism familiyangizni to\'liq kiriting');

  const s = await getSettings();
  const cls = await pool.query('SELECT id FROM classes WHERE id = $1', [classId]);
  if (!cls.rowCount) throw new HttpError(404, 'Sinf topilmadi');
  if (s.camera_mode === 'required' && req.body?.camera !== true) {
    throw new HttpError(400, 'Bu test uchun kamera yoqilishi shart');
  }

  const subject = cleanText(req.body?.subject, 60);
  const ids = await pickQuestions(classId, subject, s);
  if (!ids.length) throw new HttpError(404, subject ? `${classId} uchun "${subject}" fanidan savollar yo'q` : 'Bu sinf uchun hali savollar kiritilmagan');

  const token = crypto.randomBytes(32).toString('base64url');
  let a;
  try {
    const { rows } = await pool.query(`
      INSERT INTO attempts (class_id, student_name, team_name, token_hash, question_ids, total,
                            question_started_at, camera, ip, user_agent, subject)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
      [classId, studentName, teamName || '-', sha256(token), ids, ids.length, new Date(),
        req.body?.camera === true, (req.ip || '').slice(0, 64), cleanText(req.get('user-agent'), 300), subject]);
    a = rows[0];
  } catch (err) {
    if (err.code === '23505') {
      throw new HttpError(409, `Siz ${subject ? `"${subject}" fanidan ` : ''}bu testni allaqachon boshlagansiz. Qayta topshirish uchun o'qituvchingizga murojaat qiling.`);
    }
    throw err;
  }
  res.status(201).json({ token, ...(await buildState(pool, a, s)) });
}));

app.get('/api/attempt/state', asyncH(async (req, res) => {
  const s = await getSettings();
  const state = await withAttempt(req, async (db, a) => {
    const current = await syncAttempt(db, a, s);
    if (a.status === 'active') {
      if (req.query.resume === '1') await logEvent(db, a, 'reload', 'Sahifa qayta ochildi', false);
      await db.query('UPDATE attempts SET last_seen_at = $2 WHERE id = $1', [a.id, new Date()]);
    }
    return buildState(db, a, s, current);
  });
  res.json(state);
}));

app.post('/api/attempt/answer', asyncH(async (req, res) => {
  const s = await getSettings();
  const questionId = Number(req.body?.question_id);
  const raw = req.body?.answer == null ? null : String(req.body.answer).slice(0, 1000);

  const state = await withAttempt(req, async (db, a) => {
    let current = await syncAttempt(db, a, s);
    if (a.status === 'active' && current && current.id === questionId) {
      const t = current;
      // Yozma javob: bo'sh qator — javobsiz
      const answer = t.qtype === 'open' && raw !== null ? (cleanText(raw, 200) || null) : raw;
      if (answer !== null && t.qtype !== 'open' && !uniqueOptions(t.options).includes(answer)) {
        throw new HttpError(400, 'Noto\'g\'ri javob varianti');
      }
      const elapsed = Date.now() - new Date(a.question_started_at).getTime();
      await recordAnswer(db, a, t, answer, elapsed, answer === null);

      // Savolni o'qishga ham ulgurmay javob berish — shubhali
      const fastMs = Math.max(1500, Math.min(6000, t.question.length * 25));
      if (answer !== null && elapsed < fastMs) {
        await logEvent(db, a, 'fast_answer', `${(elapsed / 1000).toFixed(1)} soniyada javob berdi`, false);
      }

      a.current_index += 1;
      a.question_started_at = new Date();
      await db.query('UPDATE attempts SET current_index = $2, question_started_at = $3, last_seen_at = $3 WHERE id = $1',
        [a.id, a.current_index, a.question_started_at]);
      current = await syncAttempt(db, a, s);
    }
    return buildState(db, a, s, current);
  });
  res.json(state);
}));

// data:image/jpeg;base64,... → Buffer (yaroqsiz bo'lsa null)
function parseJpeg(dataUrl) {
  const m = /^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/.exec(typeof dataUrl === 'string' ? dataUrl : '');
  if (!m) return null;
  const buf = Buffer.from(m[1], 'base64');
  if (buf.length < 500 || buf.length > SNAPSHOT_MAX_BYTES || buf[0] !== 0xFF || buf[1] !== 0xD8) return null;
  return buf;
}

app.post('/api/attempt/event', asyncH(async (req, res) => {
  const type = String(req.body?.type || '');
  if (!VIOLATION_TYPES.has(type) && !WARNING_TYPES.has(type)) throw new HttpError(400, 'Noma\'lum hodisa');
  const detail = cleanText(req.body?.detail, 200);
  // Hodisa paytidagi kamera kadri (dalil) — hodisaga bog'lanib saqlanadi
  const image = parseJpeg(req.body?.image);
  const s = await getSettings();

  const out = await withAttempt(req, async (db, a) => {
    if (a.status !== 'active') return { status: a.status, violations: a.violations, max_violations: s.max_violations };

    let snapshotId = null;
    if (image) {
      const r = await db.query('INSERT INTO attempt_snapshots (attempt_id, image, reason) VALUES ($1, $2, $3) RETURNING id',
        [a.id, image, type]);
      snapshotId = r.rows[0].id;
      await db.query('UPDATE attempts SET last_snapshot_at = $2 WHERE id = $1', [a.id, new Date()]);
    }

    let counted = false;
    if (VIOLATION_TYPES.has(type)) {
      const now = new Date();
      const recent = a.last_violation_at && now - new Date(a.last_violation_at) < VIOLATION_DEDUP_MS;
      if (!recent) {
        counted = true;
        a.violations += 1;
      }
      await db.query('UPDATE attempts SET violations = $2, last_violation_at = $3 WHERE id = $1', [a.id, a.violations, now]);
    }
    await logEvent(db, a, type, detail, counted, snapshotId);

    if (counted && s.max_violations > 0 && a.violations >= s.max_violations) {
      await logEvent(db, a, 'auto_terminated', `${a.violations} ta qoidabuzarlik`, false);
      await finishAttempt(db, a, 'terminated');
    }
    return { status: a.status, violations: a.violations, max_violations: s.max_violations, counted };
  });
  res.json(out);
}));

app.post('/api/attempt/heartbeat', asyncH(async (req, res) => {
  const s = await getSettings();
  const out = await withAttempt(req, async (db, a) => {
    if (a.status === 'active') {
      const now = new Date();
      const gap = now - new Date(a.last_seen_at);
      if (gap > 25000) await logEvent(db, a, 'connection_gap', `${Math.round(gap / 1000)} soniya aloqa yo'q`, false);
      await db.query('UPDATE attempts SET last_seen_at = $2 WHERE id = $1', [a.id, now]);
      await syncAttempt(db, a, s);
    }
    return { status: a.status, violations: a.violations, max_violations: s.max_violations };
  });
  res.json(out);
}));

app.post('/api/attempt/snapshot', asyncH(async (req, res) => {
  const buf = parseJpeg(req.body?.image);
  if (!buf) throw new HttpError(400, 'Rasm yaroqsiz');
  const reason = cleanText(req.body?.reason, 40) || 'live';
  const token = req.get('x-attempt-token') || '';
  if (!token || token.length > 100) throw new HttpError(401, 'Test sessiyasi topilmadi');

  // Qulf (FOR UPDATE) ishlatilmaydi — kadrlar tez-tez keladi va javob berishni sekinlashtirmasligi kerak
  const { rows } = await pool.query(
    'SELECT id, status, last_snapshot_at FROM attempts WHERE token_hash = $1', [sha256(token)]);
  const a = rows[0];
  if (!a) throw new HttpError(404, 'Test sessiyasi topilmadi');
  if (a.status !== 'active') return res.json({ ok: true, status: a.status });

  const nextMs = (watchedUntil.get(a.id) || 0) > Date.now() ? WATCHED_FRAME_MS : LIVE_FRAME_MS;

  if (reason === 'live') {
    // Jonli kuzatuv kadri faqat xotirada turadi (bazaga yozilmaydi)
    liveFrames.set(a.id, { buf, at: Date.now() });
  } else {
    // Bazaga faqat dalil suratlari: test boshida va qoidabuzarlik/ogohlantirish paytida.
    // Bir xil dalil ikki marta yuborilmasligi uchun 2 soniyalik himoya.
    const since = a.last_snapshot_at ? Date.now() - new Date(a.last_snapshot_at) : Infinity;
    if (since > 2000) {
      await pool.query('INSERT INTO attempt_snapshots (attempt_id, image, reason) VALUES ($1, $2, $3)', [a.id, buf, reason]);
      await pool.query('UPDATE attempts SET last_snapshot_at = $2 WHERE id = $1', [a.id, new Date()]);
    }
  }
  res.json({ ok: true, next_ms: nextMs });
}));

// ═══════════════════════════════════════════════════════════════════════════════
// ADMIN API
// ═══════════════════════════════════════════════════════════════════════════════

app.post('/api/admin/login', loginLimiter, asyncH(async (req, res) => {
  const username = cleanText(req.body?.username, 50).toLowerCase();
  const password = typeof req.body?.password === 'string' ? req.body.password.slice(0, 128) : '';
  if (!username || !password) throw new HttpError(400, 'Login va parolni kiriting');

  const { rows } = await pool.query('SELECT * FROM admins WHERE username = $1', [username]);
  const admin = rows[0];
  if (admin?.locked_until && new Date(admin.locked_until) > new Date()) {
    const min = Math.ceil((new Date(admin.locked_until) - Date.now()) / 60000);
    throw new HttpError(429, `Juda ko'p noto'g'ri urinish. ${min} daqiqadan keyin qayta urinib ko'ring.`);
  }

  const ok = await bcrypt.compare(password, admin ? admin.password_hash : DUMMY_HASH);
  if (!admin || !ok) {
    if (admin) {
      await pool.query(`
        UPDATE admins SET
          failed_logins = CASE WHEN failed_logins + 1 >= $2 THEN 0 ELSE failed_logins + 1 END,
          locked_until  = CASE WHEN failed_logins + 1 >= $2 THEN NOW() + interval '15 minutes' ELSE locked_until END
        WHERE id = $1`, [admin.id, MAX_FAILED_LOGINS]);
    }
    throw new HttpError(401, 'Login yoki parol noto\'g\'ri');
  }

  await pool.query('UPDATE admins SET failed_logins = 0, locked_until = NULL WHERE id = $1', [admin.id]);
  res.json({ token: signAdmin(admin), username: admin.username });
}));

app.use('/api/admin', requireAdmin);

app.get('/api/admin/me', asyncH(async (req, res) => {
  const { rows: [stats] } = await pool.query(`
    SELECT (SELECT count(*) FROM classes)::int AS classes,
           (SELECT count(*) FROM tests)::int AS tests,
           (SELECT count(*) FROM attempts)::int AS attempts,
           (SELECT count(*) FROM attempts WHERE status = 'active')::int AS active`);
  res.json({ username: req.admin.username, stats });
}));

app.post('/api/admin/password', asyncH(async (req, res) => {
  await verifyAdminPassword(req.admin.id, req.body?.current_password);
  const next = req.body?.new_password;
  const problem = passwordProblem(next, req.admin.username);
  if (problem) throw new HttpError(400, problem);
  const { rows } = await pool.query(`
    UPDATE admins SET password_hash = $2, token_version = token_version + 1, updated_at = NOW()
    WHERE id = $1 RETURNING *`, [req.admin.id, await bcrypt.hash(next, BCRYPT_COST)]);
  // Boshqa qurilmalardagi barcha sessiyalar bekor bo'ladi, shu qurilmaga yangi token
  res.json({ token: signAdmin(rows[0]) });
}));

// ─── Sinflar ───
app.get('/api/admin/classes', asyncH(async (req, res) => {
  const { rows } = await pool.query(`
    SELECT c.id, (SELECT count(*) FROM tests t WHERE t.class_id = c.id)::int AS test_count,
           COALESCE((SELECT json_agg(json_build_object('subject', s.subject, 'count', s.n) ORDER BY s.subject)
                     FROM (SELECT subject, count(*)::int AS n FROM tests t WHERE t.class_id = c.id GROUP BY subject) s),
                    '[]'::json) AS subjects
    FROM classes c
    ORDER BY (substring(c.id from '^\\d+'))::int NULLS LAST, c.id`);
  res.json(rows);
}));

app.post('/api/admin/classes', asyncH(async (req, res) => {
  const id = cleanText(req.body?.id, 60);
  if (!CLASS_ID_RE.test(id)) throw new HttpError(400, 'Sinf nomi 1–50 belgi: harf, raqam, probel, - _ . \' (masalan: 7-A)');
  try {
    await pool.query('INSERT INTO classes (id) VALUES ($1)', [id]);
  } catch (err) {
    if (err.code === '23505') throw new HttpError(409, 'Bu sinf allaqachon mavjud');
    throw err;
  }
  res.status(201).json({ id });
}));

app.delete('/api/admin/classes/:id', asyncH(async (req, res) => {
  const r = await pool.query('DELETE FROM classes WHERE id = $1', [req.params.id]);
  if (!r.rowCount) throw new HttpError(404, 'Sinf topilmadi');
  res.json({ success: true });
}));

// ─── Savol rasmlari ───
const IMAGE_MAX_BYTES = 1.5 * 1024 * 1024;

// data:image/png;base64,... → test_images ga saqlaydi (bir xil rasm bir marta), id qaytaradi
async function saveTestImage(db, dataUrl) {
  if (!dataUrl) return null;
  const m = /^data:(image\/(?:png|jpeg|gif|webp));base64,([A-Za-z0-9+/=]+)$/.exec(String(dataUrl));
  if (!m) throw new HttpError(400, 'Rasm formati PNG, JPG, GIF yoki WEBP bo\'lishi kerak');
  const buf = Buffer.from(m[2], 'base64');
  if (!buf.length || buf.length > IMAGE_MAX_BYTES) throw new HttpError(400, 'Rasm hajmi 1.5 MB dan oshmasin');
  const hash = crypto.createHash('sha256').update(buf).digest('hex');
  const { rows } = await db.query(`
    INSERT INTO test_images (hash, mime, data) VALUES ($1, $2, $3)
    ON CONFLICT (hash) DO UPDATE SET hash = EXCLUDED.hash RETURNING id`, [hash, m[1], buf]);
  return rows[0].id;
}

// ─── Savollar ───
// Turi: 'choice' (variantli) yoki 'open' (o'quvchi javobni yozadi).
// Xato javoblar massiv (wrong_answers) yoki alohida maydonlar (wrong1, wrong2, wrong3) ko'rinishida kelishi mumkin
function parseTestBody(body) {
  const question = cleanMultiline(body?.question, 2000);
  const correct = cleanText(body?.correct_answer, 300);
  const qtype = body?.type === 'open' || body?.qtype === 'open' ? 'open' : 'choice';
  const subject = cleanText(body?.subject, 60);
  if (question.length < 3) throw new HttpError(400, 'Savol matnini kiriting');
  if (!correct) throw new HttpError(400, 'To\'g\'ri javobni kiriting');
  if (qtype === 'open') return { question, correct, options: '[]', qtype, subject };

  let options;
  if (Array.isArray(body?.options) && body.options.length) {
    // Fayldagi tartibdagi barcha variantlar (to'g'risi ham ichida)
    options = [];
    for (const o of body.options.slice(0, 8)) {
      const v = cleanText(o, 300);
      if (v && !options.includes(v)) options.push(v);
    }
    if (!options.includes(correct)) throw new HttpError(400, 'To\'g\'ri javob variantlar ichida yo\'q');
    if (options.length < 2) throw new HttpError(400, 'Kamida 2 ta variant kerak');
  } else {
    const rawWrong = Array.isArray(body?.wrong_answers)
      ? body.wrong_answers
      : [body?.wrong1, body?.wrong2, body?.wrong3, body?.wrong4];
    const wrong = [];
    for (const w of rawWrong.slice(0, 5)) {
      const v = cleanText(w, 300);
      if (v && !wrong.some(x => x.toLowerCase() === v.toLowerCase())) wrong.push(v);
    }
    if (!wrong.length) throw new HttpError(400, 'Kamida bitta xato javob kiriting');
    if (wrong.some(w => w.toLowerCase() === correct.toLowerCase())) {
      throw new HttpError(400, 'Xato javob to\'g\'ri javob bilan bir xil bo\'lmasligi kerak');
    }
    options = [correct, ...wrong];
  }
  return { question, correct, options: JSON.stringify(options), qtype, subject };
}

app.get('/api/admin/classes/:id/tests', asyncH(async (req, res) => {
  const subject = typeof req.query.subject === 'string' ? req.query.subject : null;
  const { rows } = await pool.query(`
    SELECT id, class_id, subject, qtype, image_id, sort_order, question, correct_answer, options
    FROM tests WHERE class_id = $1 AND ($2::varchar IS NULL OR subject = $2)
    ORDER BY subject, sort_order NULLS LAST, id`, [req.params.id, subject]);
  res.json(rows.map(r => ({ ...r, options: uniqueOptions(r.options) })));
}));

// Sinf+fanda xuddi shu savol bo'lsa qo'shmaydi. true = qo'shildi
async function insertTest(db, classId, t) {
  const dup = await db.query(
    'SELECT 1 FROM tests WHERE class_id = $1 AND subject = $2 AND lower(btrim(question)) = lower($3) LIMIT 1',
    [classId, t.subject || '', t.question]);
  if (dup.rowCount) return false;
  await db.query(`
    INSERT INTO tests (class_id, subject, qtype, image_id, sort_order, question, correct_answer, options)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [classId, t.subject || '', t.qtype || 'choice', t.image_id || null, t.sort_order ?? null, t.question, t.correct, t.options]);
  return true;
}

// Bitta savolni bir yoki bir nechta sinfga qo'shish
app.post('/api/admin/classes/:id/tests', asyncH(async (req, res) => {
  const t = parseTestBody(req.body);
  const targets = Array.isArray(req.body?.target_classes) ? req.body.target_classes.filter(x => typeof x === 'string') : [];
  const wanted = [...new Set([req.params.id, ...targets])].slice(0, 100);
  const { rows } = await pool.query('SELECT id FROM classes WHERE id = ANY($1)', [wanted]);
  const existing = new Set(rows.map(r => r.id));
  if (!existing.has(req.params.id)) throw new HttpError(404, 'Sinf topilmadi');

  const added = [];
  const skipped = [];
  await tx(async db => {
    t.image_id = await saveTestImage(db, req.body?.image);
    for (const cls of wanted.filter(c => existing.has(c))) {
      (await insertTest(db, cls, t) ? added : skipped).push(cls);
    }
  });
  res.status(201).json({ added, skipped });
}));

// Ommaviy yuklash (JSON/CSV fayldan): [{ class_id, subject, question, correct_answer, wrong1, wrong2, wrong3 }]
app.post('/api/admin/tests/bulk', asyncH(async (req, res) => {
  const items = Array.isArray(req.body?.items) ? req.body.items : null;
  if (!items || !items.length) throw new HttpError(400, 'Fayl bo\'sh');
  if (items.length > 2000) throw new HttpError(400, 'Bir martada ko\'pi bilan 2000 ta savol yuklash mumkin');

  const { rows } = await pool.query('SELECT id FROM classes');
  const classes = new Set(rows.map(r => r.id));
  let added = 0;
  let skipped = 0;
  const errors = [];
  await tx(async db => {
    for (let i = 0; i < items.length; i++) {
      const item = items[i] || {};
      const classId = cleanText(String(item.class_id ?? ''), 50);
      try {
        if (!classes.has(classId)) throw new HttpError(400, `"${classId}" sinfi topilmadi`);
        const t = parseTestBody(item);
        if (await insertTest(db, classId, t)) added++;
        else skipped++;
      } catch (err) {
        if (!(err instanceof HttpError)) throw err;
        errors.push({ row: i + 1, error: err.message });
      }
    }
  });
  res.json({ added, skipped, failed: errors.length, errors: errors.slice(0, 30) });
}));

// Word fayldan import (brauzerda o'qilgan): sinf + fan bo'yicha savollar to'plami.
// { sets: [{ class_id, subject, questions: [{ text, type, options, correct, image }] }], replace: true }
// replace — shu sinf+fandagi eski savollar o'chirilib, yangilari fayldagi tartibda yoziladi.
app.post('/api/admin/tests/import', asyncH(async (req, res) => {
  const sets = Array.isArray(req.body?.sets) ? req.body.sets : null;
  if (!sets || !sets.length) throw new HttpError(400, 'Yuklash uchun savollar yo\'q');
  if (sets.length > 50) throw new HttpError(400, 'Bir martada ko\'pi bilan 50 ta fayl');
  const replace = req.body?.replace !== false;

  const result = [];
  await tx(async db => {
    for (const set of sets) {
      const classId = cleanText(set?.class_id, 50);
      const subject = cleanText(set?.subject, 60);
      if (!CLASS_ID_RE.test(classId)) throw new HttpError(400, `Sinf nomi noto'g'ri: "${classId}"`);
      if (!subject) throw new HttpError(400, `${classId}: fan nomi kiritilmagan`);
      const questions = Array.isArray(set?.questions) ? set.questions : [];
      if (!questions.length || questions.length > 300) throw new HttpError(400, `${classId} ${subject}: savollar soni noto'g'ri`);

      await db.query('INSERT INTO classes (id) VALUES ($1) ON CONFLICT DO NOTHING', [classId]);
      let removed = 0;
      if (replace) {
        removed = (await db.query('DELETE FROM tests WHERE class_id = $1 AND subject = $2', [classId, subject])).rowCount;
      }
      let added = 0;
      for (let i = 0; i < questions.length; i++) {
        const q = questions[i] || {};
        let t;
        try {
          t = parseTestBody({ question: q.text, correct_answer: q.correct, type: q.type, options: q.options, subject });
        } catch (err) {
          if (err instanceof HttpError) throw new HttpError(400, `${classId} ${subject}, ${i + 1}-savol: ${err.message}`);
          throw err;
        }
        t.image_id = await saveTestImage(db, q.image);
        t.sort_order = i + 1;
        if (await insertTest(db, classId, t)) added++;
      }
      result.push({ class_id: classId, subject, added, removed });
    }
  });
  res.json({ sets: result });
}));

// Sinfdagi takroriy savollarni o'chirish (har biridan eng birinchisi qoladi; fanlar alohida)
app.post('/api/admin/classes/:id/dedup', asyncH(async (req, res) => {
  const r = await pool.query(`
    DELETE FROM tests WHERE class_id = $1 AND id NOT IN (
      SELECT min(id) FROM tests WHERE class_id = $1 GROUP BY subject, lower(btrim(question))
    )`, [req.params.id]);
  res.json({ deleted: r.rowCount });
}));

// Sinf savollarini parallel sinflarga nusxalash (2-A → 2-B, 2-C ...)
app.post('/api/admin/classes/:id/copy-to-parallel', asyncH(async (req, res) => {
  const source = req.params.id;
  if (!source.includes('-')) throw new HttpError(400, 'Sinf nomi "7-A" ko\'rinishida bo\'lishi kerak');
  const grade = source.split('-')[0];
  const { rows: tests } = await pool.query(
    'SELECT question, correct_answer, options, subject, qtype, image_id, sort_order FROM tests WHERE class_id = $1', [source]);
  if (!tests.length) throw new HttpError(400, 'Bu sinfda savol yo\'q');
  const { rows: all } = await pool.query('SELECT id FROM classes');
  const parallels = all.map(r => r.id).filter(id => id !== source && id.split('-')[0] === grade);
  if (!parallels.length) throw new HttpError(400, `${grade}-sinflar orasida boshqa parallel sinf topilmadi`);

  let added = 0;
  await tx(async db => {
    for (const cls of parallels) {
      for (const t of tests) {
        const ok = await insertTest(db, cls, {
          question: t.question, correct: t.correct_answer, options: JSON.stringify(uniqueOptions(t.options)),
          subject: t.subject, qtype: t.qtype, image_id: t.image_id, sort_order: t.sort_order
        });
        if (ok) added++;
      }
    }
  });
  res.json({ parallel_classes: parallels, added });
}));

app.put('/api/admin/tests/:id', asyncH(async (req, res) => {
  const t = parseTestBody(req.body);
  const id = parseId(req.params.id);
  await tx(async db => {
    // image: undefined — o'zgarmaydi, null — o'chiriladi, data URL — yangisi
    const imageChange = req.body?.image === undefined ? undefined : await saveTestImage(db, req.body.image);
    const r = await db.query(`
      UPDATE tests SET question = $2, correct_answer = $3, options = $4, qtype = $5, subject = $6,
             image_id = CASE WHEN $7::boolean THEN $8::int ELSE image_id END
      WHERE id = $1`,
      [id, t.question, t.correct, t.options, t.qtype, t.subject, imageChange !== undefined, imageChange ?? null]);
    if (!r.rowCount) throw new HttpError(404, 'Savol topilmadi');
  });
  res.json({ success: true });
}));

app.delete('/api/admin/tests/:id', asyncH(async (req, res) => {
  await pool.query('DELETE FROM tests WHERE id = $1', [parseId(req.params.id)]);
  res.json({ success: true });
}));

// ─── Natijalar va nazorat ───
app.get('/api/admin/attempts', asyncH(async (req, res) => {
  const classId = typeof req.query.class_id === 'string' && req.query.class_id ? req.query.class_id : null;
  const { rows } = await pool.query(`
    SELECT a.id, a.class_id, a.subject, a.student_name, a.team_name, a.status, a.score, a.total, a.violations,
           a.current_index, cardinality(a.question_ids) AS question_count, a.camera,
           a.started_at, a.finished_at, a.last_seen_at,
           COALESCE((SELECT json_object_agg(type, n) FROM (
             SELECT type, count(*)::int AS n FROM attempt_events e WHERE e.attempt_id = a.id GROUP BY type
           ) s), '{}'::json) AS event_counts,
           (SELECT count(*) FROM attempt_answers x WHERE x.attempt_id = a.id)::int AS answered,
           (SELECT count(*) FROM attempt_snapshots p WHERE p.attempt_id = a.id)::int AS snapshots
    FROM attempts a
    WHERE ($1::varchar IS NULL OR a.class_id = $1)
    ORDER BY (a.status = 'active') DESC, a.started_at DESC
    LIMIT 1000`, [classId]);
  res.json(rows.map(r => ({ ...r, risk: r.status === 'legacy' ? 'unknown' : riskLevel(r, r.event_counts) })));
}));

app.get('/api/admin/attempts/:id', asyncH(async (req, res) => {
  const id = parseId(req.params.id);
  const { rows } = await pool.query(`
    SELECT id, class_id, subject, student_name, team_name, status, score, total, violations, current_index,
           cardinality(question_ids) AS question_count, camera, ip, user_agent,
           started_at, finished_at, last_seen_at
    FROM attempts WHERE id = $1`, [id]);
  if (!rows[0]) throw new HttpError(404, 'Natija topilmadi');
  const [answers, events, snapshots] = await Promise.all([
    pool.query(`SELECT test_id, question, correct_answer, answer, is_correct, time_ms, timed_out, created_at
                FROM attempt_answers WHERE attempt_id = $1 ORDER BY id`, [id]),
    pool.query(`SELECT id, type, detail, is_violation, question_index, snapshot_id, created_at
                FROM attempt_events WHERE attempt_id = $1 ORDER BY id`, [id]),
    pool.query(`SELECT id, reason, created_at FROM attempt_snapshots WHERE attempt_id = $1 ORDER BY id`, [id])
  ]);
  const counts = {};
  for (const e of events.rows) counts[e.type] = (counts[e.type] || 0) + 1;
  const a = rows[0];
  res.json({
    ...a,
    risk: a.status === 'legacy' ? 'unknown' : riskLevel(a, counts),
    event_counts: counts,
    answers: answers.rows,
    events: events.rows,
    snapshots: snapshots.rows
  });
}));

app.get('/api/admin/snapshots/:id', asyncH(async (req, res) => {
  const { rows } = await pool.query('SELECT image FROM attempt_snapshots WHERE id = $1', [parseId(req.params.id)]);
  if (!rows[0]) throw new HttpError(404, 'Rasm topilmadi');
  res.set('Content-Type', 'image/jpeg').set('Cache-Control', 'private, no-store').send(rows[0].image);
}));

app.post('/api/admin/attempts/:id/terminate', asyncH(async (req, res) => {
  const id = parseId(req.params.id);
  await tx(async db => {
    const { rows } = await db.query('SELECT * FROM attempts WHERE id = $1 FOR UPDATE', [id]);
    const a = rows[0];
    if (!a) throw new HttpError(404, 'Natija topilmadi');
    if (a.status !== 'active') throw new HttpError(409, 'Test allaqachon yakunlangan');
    await logEvent(db, a, 'admin_terminated', `Admin: ${req.admin.username}`, false);
    await finishAttempt(db, a, 'terminated');
  });
  res.json({ success: true });
}));

app.delete('/api/admin/attempts/:id', asyncH(async (req, res) => {
  await pool.query('DELETE FROM attempts WHERE id = $1', [parseId(req.params.id)]);
  res.json({ success: true });
}));

function parseIdList(v, max) {
  if (!Array.isArray(v) || !v.length) throw new HttpError(400, 'Hech narsa tanlanmagan');
  if (v.length > max) throw new HttpError(400, `Bir martada ko'pi bilan ${max} ta`);
  return [...new Set(v.map(parseId))];
}

// Bir nechta natijani birdan o'chirish (parol bilan tasdiqlanadi)
app.post('/api/admin/attempts/bulk-delete', asyncH(async (req, res) => {
  await verifyAdminPassword(req.admin.id, req.body?.password);
  const ids = parseIdList(req.body?.ids, 5000);
  const r = await pool.query('DELETE FROM attempts WHERE id = ANY($1::int[])', [ids]);
  for (const id of ids) liveFrames.delete(id);
  res.json({ deleted: r.rowCount });
}));

// PDF hisobot uchun bir nechta natijaning to'liq ma'lumoti bitta so'rovda
app.post('/api/admin/attempts/report', asyncH(async (req, res) => {
  const ids = parseIdList(req.body?.ids, 500);
  const [attempts, answers, events, snapshots] = await Promise.all([
    pool.query(`
      SELECT id, class_id, subject, student_name, team_name, status, score, total, violations, current_index,
             cardinality(question_ids) AS question_count, camera, ip, user_agent, started_at, finished_at
      FROM attempts WHERE id = ANY($1::int[])`, [ids]),
    pool.query(`SELECT attempt_id, question, correct_answer, answer, is_correct, time_ms, timed_out
                FROM attempt_answers WHERE attempt_id = ANY($1::int[]) ORDER BY id`, [ids]),
    pool.query(`SELECT attempt_id, id, type, detail, is_violation, question_index, snapshot_id, created_at
                FROM attempt_events WHERE attempt_id = ANY($1::int[]) ORDER BY id`, [ids]),
    pool.query(`SELECT attempt_id, id, reason, created_at
                FROM attempt_snapshots WHERE attempt_id = ANY($1::int[]) ORDER BY id`, [ids])
  ]);
  const group = rows => {
    const m = new Map();
    for (const r of rows) {
      if (!m.has(r.attempt_id)) m.set(r.attempt_id, []);
      m.get(r.attempt_id).push(r);
    }
    return m;
  };
  const ans = group(answers.rows);
  const ev = group(events.rows);
  const snap = group(snapshots.rows);
  res.json(attempts.rows.map(a => {
    const evs = ev.get(a.id) || [];
    const counts = {};
    for (const e of evs) counts[e.type] = (counts[e.type] || 0) + 1;
    return {
      ...a,
      risk: a.status === 'legacy' ? 'unknown' : riskLevel(a, counts),
      event_counts: counts,
      answers: ans.get(a.id) || [],
      events: evs,
      snapshots: snap.get(a.id) || []
    };
  }));
}));

// ─── Jonli kuzatuv ───
app.get('/api/admin/live', asyncH(async (req, res) => {
  const { rows } = await pool.query(`
    SELECT a.id, a.class_id, a.subject, a.student_name, a.current_index, cardinality(a.question_ids) AS question_count,
           a.violations, a.camera, a.started_at, a.last_seen_at, a.last_violation_at,
           (SELECT e.type FROM attempt_events e WHERE e.attempt_id = a.id AND e.is_violation
             ORDER BY e.id DESC LIMIT 1) AS last_violation_type,
           (SELECT json_build_object('id', e.id, 'type', e.type, 'detail', e.detail, 'at', e.created_at)
              FROM attempt_events e
             WHERE e.attempt_id = a.id AND e.type = ANY($1) AND e.created_at > NOW() - interval '60 seconds'
             ORDER BY e.id DESC LIMIT 1) AS last_alert,
           (SELECT count(*) FROM attempt_events e
             WHERE e.attempt_id = a.id AND e.type = ANY($1))::int AS alert_count
    FROM attempts a WHERE a.status = 'active'
    ORDER BY a.class_id, a.student_name`, [ALERT_TYPES]);
  const now = Date.now();
  res.json(rows.map(r => {
    const f = liveFrames.get(r.id);
    return { ...r, frame_at: f && now - f.at < LIVE_FRAME_TTL_MS ? new Date(f.at) : null };
  }));
}));

app.get('/api/admin/live/:id/frame', asyncH(async (req, res) => {
  const id = parseId(req.params.id);
  // ?focus=1 — admin shu o'quvchini katta oynada ko'rmoqda: o'quvchi kadrni har soniyada yuboradi
  if (req.query.focus === '1') watchedUntil.set(id, Date.now() + 8000);
  const f = liveFrames.get(id);
  if (!f || Date.now() - f.at > LIVE_FRAME_TTL_MS) throw new HttpError(404, 'Kadr yo\'q');
  res.set('Content-Type', 'image/jpeg').set('Cache-Control', 'private, no-store').send(f.buf);
}));

// ─── Sozlamalar ───
app.get('/api/admin/settings', asyncH(async (req, res) => {
  res.json(await getSettings());
}));

app.put('/api/admin/settings', asyncH(async (req, res) => {
  const next = normalizeSettings(req.body, await getSettings());
  await pool.query(`
    INSERT INTO settings (key, value) VALUES ('app', $1)
    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, [JSON.stringify(next)]);
  settingsCache = next;
  settingsCachedAt = Date.now();
  res.json(next);
}));

app.post('/api/admin/clear-all', asyncH(async (req, res) => {
  await verifyAdminPassword(req.admin.id, req.body?.password);
  await tx(async db => {
    await db.query('DELETE FROM attempts');
    await db.query('DELETE FROM tests');
    await db.query('DELETE FROM classes');
    const legacy = await db.query(`SELECT to_regclass('public.results') AS t`);
    if (legacy.rows[0].t) await db.query('DELETE FROM results');
  });
  res.json({ success: true });
}));

// ─── 404 va xatolar ────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Topilmadi' }));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'JSON noto\'g\'ri' });
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'So\'rov hajmi juda katta' });
  console.error(err);
  res.status(500).json({ error: 'Server xatosi' });
});

// ─── TASHLAB KETILGAN TESTLARNI YOPISH ─────────────────────────────────────────
async function sweepAbandoned() {
  for (const [id, f] of liveFrames) {
    if (Date.now() - f.at > LIVE_FRAME_TTL_MS) liveFrames.delete(id);
  }
  for (const [id, until] of watchedUntil) {
    if (until < Date.now()) watchedUntil.delete(id);
  }
  const { rows } = await pool.query(
    `SELECT id FROM attempts WHERE status = 'active' AND last_seen_at < NOW() - make_interval(mins => $1)`,
    [ABANDON_AFTER_MIN]);
  for (const { id } of rows) {
    await tx(async db => {
      const r = await db.query('SELECT * FROM attempts WHERE id = $1 FOR UPDATE', [id]);
      const a = r.rows[0];
      if (!a || a.status !== 'active') return;
      await logEvent(db, a, 'abandoned', `${ABANDON_AFTER_MIN} daqiqadan ortiq aloqa bo'lmadi`, false);
      await finishAttempt(db, a, 'abandoned');
    });
  }
}

// ─── START SERVER ──────────────────────────────────────────────────────────────
initDB()
  .then(seedAdmin)
  .then(() => {
    const server = app.listen(PORT, () => console.log(`🚀 Server ${PORT}-portda ishlamoqda`));
    setInterval(() => sweepAbandoned().catch(err => console.error('Sweep xatosi:', err.message)), 60 * 1000).unref();
    const shutdown = () => server.close(() => pool.end().then(() => process.exit(0)));
    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
  })
  .catch(err => fatal('Database ulanishda xatolik: ' + err.message));
