require("dotenv").config();
console.log("REDIRECT URI:", process.env.GOOGLE_REDIRECT_URI);
// server.js
const { google } = require("googleapis");
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const session = require("express-session");
const { DatabaseSync } = require("node:sqlite");


const app = express();

let events = []; // simple in-memory log (replace with DB in production)
let userProgress = {};
let supporterProfiles = {};
let supporterStats = {};
let creatorStats = {};
let creatorProfiles = {};

app.use(session({
  secret: "change-this-secret-later",
  resave: false,
  saveUninitialized: false
}));

app.use(bodyParser.json({ limit: "10mb" }));

const DEFAULT_CREATOR = process.env.DEFAULT_CREATOR || "@5thdimentionalbeing367";

app.get("/", (req, res) => {
  res.redirect(`/${encodeURIComponent(DEFAULT_CREATOR)}`);
});

app.get(["/Support Creator.html", "/Support%20Creator.html"], (req, res) => {
  res.redirect(`/${encodeURIComponent(DEFAULT_CREATOR)}`);
});

app.use(express.static('public'));

const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);
app.get("/auth/youtube", (req, res) => {
  const url = oauth2Client.generateAuthUrl({
    access_type: "offline",
    scope: ["https://www.googleapis.com/auth/youtube.readonly"],
    prompt: "consent"
  });

  res.redirect(url);
});

app.get("/auth/youtube/callback", async (req, res) => {
  const { code } = req.query;

  const { tokens } = await oauth2Client.getToken(code);
  oauth2Client.setCredentials(tokens);

  const youtube = google.youtube({
    version: "v3",
    auth: oauth2Client
  });

  const response = await youtube.channels.list({
    part: ["snippet"],
    mine: true
  });

  const channel = response.data.items?.[0];

  const creatorProfile = {
    slug: channel.snippet.customUrl || channel.id,
    displayName: channel.snippet.title,
    profileImage: channel.snippet.thumbnails.default.url
  };

  creatorProfiles[creatorProfile.slug] = creatorProfile;
saveData();
req.session.creatorProfile = creatorProfile;

req.session.save(() => {
  res.redirect("/dashboard");
});
});



// ---------- Data storage ----------

const DATA_DIR = path.join(__dirname, "data");
const DB_PATH = path.join(DATA_DIR, "app.sqlite");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const db = new DatabaseSync(DB_PATH);

db.exec(`
  PRAGMA journal_mode = WAL;
  CREATE TABLE IF NOT EXISTS app_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS rate_limit_hits (
    bucket TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_rate_limit_hits_bucket_time
    ON rate_limit_hits(bucket, created_at);
`);

const getStateStmt = db.prepare("SELECT value FROM app_state WHERE key = ?");
const setStateStmt = db.prepare(`
  INSERT INTO app_state (key, value, updated_at)
  VALUES (?, ?, ?)
  ON CONFLICT(key) DO UPDATE SET
    value = excluded.value,
    updated_at = excluded.updated_at
`);

function readState(key, fallback) {
  const row = getStateStmt.get(key);
  if (!row) return fallback;

  try {
    return JSON.parse(row.value);
  } catch (err) {
    console.error(`Could not parse DB state for ${key}:`, err);
    return fallback;
  }
}

function writeState(key, value) {
  setStateStmt.run(key, JSON.stringify(value), Date.now());
}

function hasPersistedState() {
  return Boolean(getStateStmt.get("creatorStats"));
}

function migrateJsonDataIfNeeded() {
  if (hasPersistedState() || !fs.existsSync("data.json")) return;

  try {
    const data = JSON.parse(fs.readFileSync("data.json", "utf8"));

    writeState("userProgress", data.userProgress || {});
    writeState("creatorStats", data.creatorStats || {});
    writeState("events", data.events || []);
    writeState("supporterProfiles", data.supporterProfiles || {});
    writeState("supporterStats", data.supporterStats || {});
    writeState("creatorProfiles", data.creatorProfiles || {});

    console.log("Migrated data.json into data/app.sqlite");
  } catch (err) {
    console.error("Could not migrate data.json, starting with empty DB state:", err);
  }
}

migrateJsonDataIfNeeded();

userProgress = readState("userProgress", {});
creatorStats = readState("creatorStats", {});
events = readState("events", []);
supporterProfiles = readState("supporterProfiles", {});
supporterStats = readState("supporterStats", {});
creatorProfiles = readState("creatorProfiles", {});

// ---------- Helpers ----------
function hashFingerprint(fingerprintString) {
  return crypto.createHash('sha256').update(fingerprintString).digest('hex');
}

function getClientIp(req) {
  const forwarded = String(req.headers["x-forwarded-for"] || "")
    .split(",")[0]
    .trim();

  return forwarded || req.socket.remoteAddress || req.ip || "unknown";
}

function getDeviceProgressKey(req, fingerprint) {
  return hashFingerprint(`${getClientIp(req)}|${String(fingerprint || "").trim()}`);
}

const insertRateLimitHitStmt = db.prepare(
  "INSERT INTO rate_limit_hits (bucket, created_at) VALUES (?, ?)"
);
const countRateLimitHitsStmt = db.prepare(
  "SELECT COUNT(*) AS count, MIN(created_at) AS oldest FROM rate_limit_hits WHERE bucket = ? AND created_at >= ?"
);
const pruneRateLimitHitsStmt = db.prepare(
  "DELETE FROM rate_limit_hits WHERE created_at < ?"
);
let lastRateLimitPrune = 0;

function getRateLimitBucket(req, scope) {
  const fingerprint = req.body?.fingerprint || "";
  return hashFingerprint(`${scope}|${getClientIp(req)}|${String(fingerprint).slice(0, 400)}`);
}

function checkRateLimit(req, scope, windowMs, maxHits) {
  const now = Date.now();
  const cutoff = now - windowMs;

  if (now - lastRateLimitPrune > 60_000) {
    pruneRateLimitHitsStmt.run(now - 24 * 60 * 60 * 1000);
    lastRateLimitPrune = now;
  }

  const bucket = getRateLimitBucket(req, scope);
  const row = countRateLimitHitsStmt.get(bucket, cutoff);
  const count = Number(row?.count || 0);

  if (count >= maxHits) {
    const oldest = Number(row?.oldest || now);
    return {
      allowed: false,
      retryAfter: Math.max(1, Math.ceil((oldest + windowMs - now) / 1000))
    };
  }

  insertRateLimitHitStmt.run(bucket, now);
  return { allowed: true, retryAfter: 0 };
}

function enforceRateLimit(scope, windowMs, maxHits) {
  return (req, res, next) => {
    const limit = checkRateLimit(req, scope, windowMs, maxHits);

    if (!limit.allowed) {
      res.set("Retry-After", String(limit.retryAfter));
      return res.status(429).json({
        success: false,
        message: "Too many attempts. Try again soon.",
        wait: limit.retryAfter
      });
    }

    next();
  };
}

function isLocalRequest(req) {
  const ip = getClientIp(req);
  return ip === "::1" || ip === "127.0.0.1" || ip === "::ffff:127.0.0.1";
}

function requireDevAccess(req, res, next) {
  const token = req.headers["x-dev-token"] || req.query.token;

  if (process.env.DEV_RESET_TOKEN && token === process.env.DEV_RESET_TOKEN) {
    return next();
  }

  if (process.env.NODE_ENV !== "production" && isLocalRequest(req)) {
    return next();
  }

  return res.status(403).json({
    success: false,
    message: "Dev reset is locked."
  });
}

function getToday(timeZone) {
  return new Intl.DateTimeFormat('en-CA', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  }).format(new Date());
}

function getSecondsUntilUserMidnight(timeZone) {
  const now = new Date();

  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  }).formatToParts(now);

  const map = {};
  for (const part of parts) {
    if (part.type !== 'literal') {
      map[part.type] = parseInt(part.value, 10);
    }
  }

  const userNowUtc = Date.UTC(
    map.year,
    map.month - 1,
    map.day,
    map.hour,
    map.minute,
    map.second
  );

  const nextMidnightUtc = Date.UTC(
    map.year,
    map.month - 1,
    map.day + 1,
    0,
    0,
    0
  );

  return Math.max(0, Math.floor((nextMidnightUtc - userNowUtc) / 1000));
}

function normalizeSupporterName(name) {
  return String(name || '').trim().replace(/\s+/g, ' ');
}

function validateSupporterName(name) {
  if (!name) return null;

  if (name.length > 24) {
    return 'Use 24 characters or fewer.';
  }

  if (!/^[A-Za-z0-9][A-Za-z0-9 _-]*$/.test(name)) {
    return 'Use letters, numbers, spaces, hyphens, or underscores. Start with a letter or number.';
  }

  return null;
}

function saveData() {
  db.exec("BEGIN IMMEDIATE");

  try {
    writeState("userProgress", userProgress);
    writeState("creatorStats", creatorStats);
    writeState("events", events);
    writeState("supporterProfiles", supporterProfiles);
    writeState("supporterStats", supporterStats);
    writeState("creatorProfiles", creatorProfiles);

    db.exec("COMMIT");
  } catch (err) {
    db.exec("ROLLBACK");
    throw err;
  }
}

// ---------- Config ----------
const MAX_SUPPORTS_PER_DAY = 3;
const COOLDOWN_MS = 30_000; // 30 seconds
const REWARD_PER_SUPPORT = 0.05;
const MIN_AD_WATCH_MS = 14_000; // basic backend validation
const DEFAULT_BETA_END_AT = Date.UTC(2026, 8, 1);
const parsedBetaEndAt = Date.parse(process.env.BETA_END_AT || "");
const BETA_END_AT = Number.isFinite(parsedBetaEndAt)
  ? parsedBetaEndAt
  : DEFAULT_BETA_END_AT;
const DAY_ONE_SUPPORTER_LIMIT = Math.max(
  1,
  Number(process.env.DAY_ONE_SUPPORTER_LIMIT || 5)
);
const BADGE_DEFINITIONS = [
  {
    id: "og_wave",
    label: "OG Wave",
    short: "OG",
    unlockCondition: "Support during Oscal beta",
    description: "A supporter during Oscal beta."
  },
  {
    id: "first_drop",
    label: "First Drop",
    short: "Drop",
    unlockCondition: "First successful support",
    description: "Completed a first successful support."
  },
  {
    id: "wave_starter",
    label: "Wave Starter",
    short: "Wave",
    unlockCondition: "Support 5 creators",
    description: "Supported 5 different creators."
  },
  {
    id: "fuel_provider",
    label: "Fuel Provider",
    short: "Fuel",
    unlockCondition: "Reach 25 total supports",
    description: "Reached 25 total supports."
  },
  {
    id: "day_one",
    label: "Day One",
    short: "D1",
    unlockCondition: `Be one of the first ${DAY_ONE_SUPPORTER_LIMIT} supporters of a creator`,
    description: `One of the first ${DAY_ONE_SUPPORTER_LIMIT} supporters of a creator.`
  }
];
const SPONSOR_AD_DIR = path.join(__dirname, "public", "ads");
const SPONSOR_AD_EXTENSIONS = new Set([".mp4", ".webm", ".mov", ".m4v"]);
const STICKER_DIR = path.join(__dirname, "public", "stickers");
const STICKER_EXTENSIONS = new Set([".mp4", ".webm", ".mov", ".m4v"]);
const STICKER_EXTENSION_PRIORITY = {
  ".webm": 1,
  ".mp4": 2,
  ".m4v": 3,
  ".mov": 4
};

function getSponsorAds() {
  try {
    if (!fs.existsSync(SPONSOR_AD_DIR)) return [];

    return fs
      .readdirSync(SPONSOR_AD_DIR)
      .filter(file => SPONSOR_AD_EXTENSIONS.has(path.extname(file).toLowerCase()))
      .map(file => ({
        file,
        title: path.basename(file, path.extname(file)).replace(/[-_]+/g, " "),
        url: `/ads/${encodeURIComponent(file)}`
      }));
  } catch (err) {
    console.error("Could not read sponsor ads:", err);
    return [];
  }
}

app.get("/api/sponsor-ad", enforceRateLimit("sponsor-ad", 60_000, 40), (req, res) => {
  const ads = getSponsorAds();

  if (!ads.length) {
    return res.json({
      success: true,
      ad: null,
      minimumWatchMs: MIN_AD_WATCH_MS + 1000
    });
  }

  const ad = ads[Math.floor(Math.random() * ads.length)];

  res.json({
    success: true,
    ad,
    minimumWatchMs: MIN_AD_WATCH_MS + 1000
  });
});

function getStickerVideos() {
  try {
    if (!fs.existsSync(STICKER_DIR)) return [];

    const stickerMap = new Map();

    fs
      .readdirSync(STICKER_DIR)
      .filter(file => STICKER_EXTENSIONS.has(path.extname(file).toLowerCase()))
      .forEach(file => {
        const ext = path.extname(file).toLowerCase();
        const key = path.basename(file, ext).toLowerCase();
        const current = stickerMap.get(key);

        if (
          current &&
          STICKER_EXTENSION_PRIORITY[current.ext] <= STICKER_EXTENSION_PRIORITY[ext]
        ) {
          return;
        }

        stickerMap.set(key, {
          ext,
          file,
          title: path.basename(file, ext).replace(/[-_]+/g, " "),
          url: `/stickers/${encodeURIComponent(file)}`
        });
      });

    return Array.from(stickerMap.values()).map(({ ext, ...sticker }) => sticker);
  } catch (err) {
    console.error("Could not read sticker videos:", err);
    return [];
  }
}

function normalizeSupporterStats(stats = {}, firstSeenAt = Date.now()) {
  const firstSeen = Number(stats.firstSeenAt || firstSeenAt || Date.now());

  return {
    firstSeenAt: firstSeen,
    lastSupportAt: Number(stats.lastSupportAt || 0),
    totalSupports: Number(stats.totalSupports || 0),
    supportedCreators:
      stats.supportedCreators && typeof stats.supportedCreators === "object"
        ? stats.supportedCreators
        : {},
    dayOneCreators:
      stats.dayOneCreators && typeof stats.dayOneCreators === "object"
        ? stats.dayOneCreators
        : {},
    equippedBadgeId:
      typeof stats.equippedBadgeId === "string"
        ? stats.equippedBadgeId
        : ""
  };
}

function getOrCreateSupporterStats(anonId, firstSeenAt = Date.now()) {
  const key = String(anonId || "").trim();
  if (!key) return normalizeSupporterStats({}, firstSeenAt);

  supporterStats[key] = normalizeSupporterStats(supporterStats[key], firstSeenAt);
  return supporterStats[key];
}

function ensureCreatorSupporterTracking(creator) {
  const stats = creatorStats[creator];
  if (!stats) return false;

  let changed = false;

  if (!stats.supporterFirstSeen || typeof stats.supporterFirstSeen !== "object") {
    stats.supporterFirstSeen = {};
    changed = true;
  }

  if (!Array.isArray(stats.supporterOrder)) {
    stats.supporterOrder = [];
    changed = true;
  }

  if (Array.isArray(stats.recentSupports)) {
    [...stats.recentSupports]
      .sort((a, b) => Number(a.time || 0) - Number(b.time || 0))
      .forEach(item => {
        const key = String(item.anonId || "").trim();
        if (!key) return;

        if (!stats.supporterFirstSeen[key]) {
          stats.supporterFirstSeen[key] = Number(item.time || Date.now());
          changed = true;
        }

        if (!stats.supporterOrder.includes(key)) {
          stats.supporterOrder.push(key);
          changed = true;
        }
      });
  }

  return changed;
}

function hydrateBadgeStateFromRecentSupports() {
  let changed = false;
  const hasSupporterStats = Object.keys(supporterStats || {}).length > 0;

  Object.entries(creatorStats).forEach(([creator, stats]) => {
    if (!stats || typeof stats !== "object") return;
    changed = ensureCreatorSupporterTracking(creator) || changed;

    if (hasSupporterStats || !Array.isArray(stats.recentSupports)) return;

    [...stats.recentSupports]
      .sort((a, b) => Number(a.time || 0) - Number(b.time || 0))
      .forEach(item => {
        const key = String(item.anonId || "").trim();
        if (!key) return;

        const supportTime = Number(item.time || Date.now());
        const supporter = getOrCreateSupporterStats(key, supportTime);
        supporter.firstSeenAt = Math.min(supporter.firstSeenAt, supportTime);
        supporter.lastSupportAt = Math.max(supporter.lastSupportAt, supportTime);
        supporter.totalSupports += 1;
        supporter.supportedCreators[creator] =
          Number(supporter.supportedCreators[creator] || 0) + 1;

        const dayOneIndex = stats.supporterOrder.indexOf(key);
        if (dayOneIndex >= 0 && dayOneIndex < DAY_ONE_SUPPORTER_LIMIT) {
          supporter.dayOneCreators[creator] = stats.supporterFirstSeen[key] || supportTime;
        }

        changed = true;
      });
  });

  if (changed) saveData();
}

function recordSupporterStats(anonId, creator, supportTime = Date.now()) {
  const key = String(anonId || "").trim();
  if (!key) return [];

  const stats = getOrCreateSupporterStats(key, supportTime);
  stats.firstSeenAt = Math.min(stats.firstSeenAt, supportTime);
  stats.lastSupportAt = supportTime;
  stats.totalSupports += 1;
  stats.supportedCreators[creator] = Number(stats.supportedCreators[creator] || 0) + 1;

  ensureCreatorSupporterTracking(creator);

  const creatorRecord = creatorStats[creator];
  if (creatorRecord && !creatorRecord.supporterFirstSeen[key]) {
    creatorRecord.supporterFirstSeen[key] = supportTime;
    creatorRecord.supporterOrder.push(key);
  }

  const dayOneIndex = creatorRecord?.supporterOrder?.indexOf(key) ?? -1;
  if (dayOneIndex >= 0 && dayOneIndex < DAY_ONE_SUPPORTER_LIMIT) {
    stats.dayOneCreators[creator] = creatorRecord.supporterFirstSeen[key] || supportTime;
  }

  return getSupporterBadges(key);
}

function getDistinctSupportedCreators(anonId) {
  const key = String(anonId || "").trim();
  const stored = supporterStats[key]?.supportedCreators;
  const creators = new Set();

  if (stored && typeof stored === "object") {
    Object.keys(stored).forEach(creator => {
      if (Number(stored[creator] || 0) > 0) creators.add(creator);
    });
  }

  Object.entries(creatorStats).forEach(([creator, stats]) => {
    if (!Array.isArray(stats.recentSupports)) return;

    if (stats.recentSupports.some(item => String(item.anonId) === key)) {
      creators.add(creator);
    }
  });

  return creators.size;
}

function getFirstSupportTime(anonId) {
  const key = String(anonId || "").trim();
  let firstSupportTime = Infinity;

  Object.values(creatorStats).forEach(stats => {
    if (!Array.isArray(stats.recentSupports)) return;

    stats.recentSupports.forEach(item => {
      if (String(item.anonId) !== key) return;
      const time = Number(item.time || 0);
      if (time > 0) firstSupportTime = Math.min(firstSupportTime, time);
    });
  });

  return Number.isFinite(firstSupportTime) ? firstSupportTime : 0;
}

function getDayOneCreatorCount(anonId) {
  const key = String(anonId || "").trim();
  const dayOneCreators = new Set(Object.keys(supporterStats[key]?.dayOneCreators || {}));

  Object.entries(creatorStats).forEach(([creator, stats]) => {
    ensureCreatorSupporterTracking(creator);

    const dayOneIndex = stats.supporterOrder?.indexOf(key) ?? -1;
    if (dayOneIndex >= 0 && dayOneIndex < DAY_ONE_SUPPORTER_LIMIT) {
      dayOneCreators.add(creator);
    }
  });

  return dayOneCreators.size;
}

function getSupporterLifetimeSupports(anonId) {
  const storedTotal = Number(supporterStats[String(anonId || "")]?.totalSupports || 0);
  if (storedTotal > 0) return storedTotal;

  let lifetimeSupports = 0;

  Object.values(creatorStats).forEach(creator => {
    if (!creator.recentSupports) return;

    creator.recentSupports.forEach(item => {
      if (String(item.anonId) === String(anonId)) {
        lifetimeSupports++;
      }
    });
  });

  return lifetimeSupports;
}

function getSupporterBadges(anonId, supportCountOverride = 0) {
  const key = String(anonId || "").trim();
  if (!key) return [];

  const stats = supporterStats[key] || {};
  const lifetimeSupports = Math.max(
    getSupporterLifetimeSupports(key),
    Number(supportCountOverride || 0)
  );
  const supportedCreatorCount = getDistinctSupportedCreators(key);
  const firstSeenAt = Number(stats.firstSeenAt || getFirstSupportTime(key) || 0);
  const dayOneCreatorCount = getDayOneCreatorCount(key);

  return BADGE_DEFINITIONS.filter(badge => {
    if (badge.id === "og_wave") {
      return lifetimeSupports >= 1 && (Date.now() <= BETA_END_AT || firstSeenAt <= BETA_END_AT);
    }

    if (badge.id === "first_drop") {
      return lifetimeSupports >= 1;
    }

    if (badge.id === "wave_starter") {
      return supportedCreatorCount >= 5;
    }

    if (badge.id === "fuel_provider") {
      return lifetimeSupports >= 25;
    }

    if (badge.id === "day_one") {
      return dayOneCreatorCount > 0;
    }

    return false;
  });
}

function getSupporterBadgeCollection(anonId, supportCountOverride = 0) {
  const unlockedIds = new Set(
    getSupporterBadges(anonId, supportCountOverride).map(badge => badge.id)
  );

  return BADGE_DEFINITIONS.map(badge => ({
    ...badge,
    unlocked: unlockedIds.has(badge.id)
  }));
}

function getEquippedSupporterBadge(anonId, supportCountOverride = 0) {
  const key = String(anonId || "").trim();
  if (!key) return null;

  const stats = supporterStats[key];
  const equippedBadgeId = stats?.equippedBadgeId || "";
  if (!equippedBadgeId) return null;

  return getSupporterBadgeCollection(key, supportCountOverride).find(
    badge => badge.id === equippedBadgeId && badge.unlocked
  ) || null;
}

function attachSupporterBadges(item) {
  return {
    ...item,
    badges: getSupporterBadgeCollection(item.anonId),
    equippedBadge: getEquippedSupporterBadge(item.anonId)
  };
}

hydrateBadgeStateFromRecentSupports();

app.get("/api/stickers", enforceRateLimit("stickers", 60_000, 60), (req, res) => {
  res.json({
    success: true,
    stickers: getStickerVideos()
  });
});

// ---------- Event endpoint ----------
app.post('/event', enforceRateLimit("event", 60_000, 24), (req, res) => {
  const {
  type,
  creator,
  fingerprint,
  anonId,
  timeZone,
  videoId = "main",
  videoTitle = "Main support page",
  videoThumbnail = "",
  platform = "unknown"
} = req.body;

  if (!type || !creator || !fingerprint || !timeZone) {
    return res.json({ success: false, message: 'Missing data' });
  }

  const typeLimit = checkRateLimit(
    req,
    `event:${type}`,
    60_000,
    type === "ad_start" || type === "ad_complete" ? 8 : 4
  );

  if (!typeLimit.allowed) {
    res.set("Retry-After", String(typeLimit.retryAfter));
    return res.status(429).json({
      success: false,
      message: "Too many support attempts. Try again soon.",
      wait: typeLimit.retryAfter
    });
  }

  const deviceProgressKey = getDeviceProgressKey(req, fingerprint);
  const today = getToday(timeZone);
  const now = Date.now();

  // init user root if first time
  if (!userProgress[deviceProgressKey]) {
    userProgress[deviceProgressKey] = {
      timeZone,
      days: {}
    };
  }

  // lock timezone to this fingerprint
  if (!userProgress[deviceProgressKey].timeZone) {
    userProgress[deviceProgressKey].timeZone = timeZone;
  }

  if (userProgress[deviceProgressKey].timeZone !== timeZone) {
    return res.json({ success: false, message: 'Timezone mismatch' });
  }

  // init daily bucket
  if (!userProgress[deviceProgressKey].days[today]) {
    userProgress[deviceProgressKey].days[today] = {
      dailyCount: 0,
      lastComplete: 0,
      adStartTime: 0
    };
  }

  const userData = userProgress[deviceProgressKey].days[today];

  // ---------- Anti-bot / self-support ----------
  if (deviceProgressKey === hashFingerprint(creator)) {
    return res.json({ success: false, message: 'Cannot support yourself' });
  }

  // ---------- ad_start ----------
  if (type === 'ad_start') {
    // cooldown
    if (now - userData.lastComplete < COOLDOWN_MS) {
      return res.json({
        success: false,
        message: 'Cooldown active',
        wait: Math.ceil((COOLDOWN_MS - (now - userData.lastComplete)) / 1000)
      });
    }

    // daily cap
    if (userData.dailyCount >= MAX_SUPPORTS_PER_DAY) {
      return res.json({
        success: false,
        message: 'Daily limit reached',
        wait: getSecondsUntilUserMidnight(timeZone)
      });
    }

    // mark ad start
    userData.adStartTime = now;
    saveData();

    return res.json({ success: true });
  }

  // ---------- ad_complete ----------
  if (type === 'ad_complete') {
    // must have started an ad first
    if (!userData.adStartTime) {
      return res.json({
        success: false,
        message: 'Ad was not started properly'
      });
    }

    // must have watched long enough
    if (now - userData.adStartTime < MIN_AD_WATCH_MS) {
      return res.json({
        success: false,
        message: 'Ad not fully watched'
      });
    }

    // re-check cooldown just in case
    if (now - userData.lastComplete < COOLDOWN_MS) {
      return res.json({
        success: false,
        message: 'Cooldown active',
        wait: Math.ceil((COOLDOWN_MS - (now - userData.lastComplete)) / 1000)
      });
    }

    // re-check daily cap just in case
    if (userData.dailyCount >= MAX_SUPPORTS_PER_DAY) {
      return res.json({
        success: false,
        message: 'Daily limit reached',
        wait: getSecondsUntilUserMidnight(timeZone)
      });
    }

    // update user
    userData.dailyCount++;
    userData.lastComplete = now;
    userData.adStartTime = 0;

    // update creator
    if (!creatorStats[creator]) {
      creatorStats[creator] = {
        supports: 0,
        earnings: 0,
        videos: {},
        recentSupports: [],
        supporterFirstSeen: {},
        supporterOrder: []
      };
    }

    creatorStats[creator].supports++;
    creatorStats[creator].earnings += REWARD_PER_SUPPORT;

if (!creatorStats[creator].recentSupports) {
  creatorStats[creator].recentSupports = [];
}
recordSupporterStats(anonId, creator, now);
const badges = getSupporterBadgeCollection(anonId);
const equippedBadge = getEquippedSupporterBadge(anonId);
const savedProfile = supporterProfiles[anonId] || {};

creatorStats[creator].recentSupports.unshift({
  name: savedProfile.name || `Anonymous #${anonId || "0000"}`,
  pfp: savedProfile.pfp || "",
  anonId,
  equippedBadge,
  emoji: "",
  time: now
});

creatorStats[creator].recentSupports = creatorStats[creator].recentSupports.slice(0, 100);

const creatorSupportsForViewer = creatorStats[creator].recentSupports.filter(item =>
  String(item.anonId) === String(anonId)
).length;
    
    if (!creatorStats[creator].videos) {
  creatorStats[creator].videos = {};
}

if (!creatorStats[creator].videos[videoId]) {
  creatorStats[creator].videos[videoId] = {
    videoId,
    videoTitle,
    videoThumbnail,
    platform,
    supports: 0
  };
}

creatorStats[creator].videos[videoId].supports++;
creatorStats[creator].videos[videoId].videoTitle = videoTitle;
creatorStats[creator].videos[videoId].videoThumbnail = videoThumbnail;
creatorStats[creator].videos[videoId].platform = platform;

    // log event once
    events.push({
      timestamp: now,
      creator,
      fingerprint: deviceProgressKey,
      type: 'support_complete',
      timeZone
    });

    saveData();

    const videos = Object.values(creatorStats[creator].videos || {});
const mostSupportedVideo =
  videos.sort((a, b) => b.supports - a.supports)[0] || null;

return res.json({
  success: true,
  supports: creatorStats[creator].supports,
  creatorSupports: creatorSupportsForViewer,
  badges,
  equippedBadge,
  mostSupportedVideo
});
  }

  return res.json({ success: false, message: 'Unknown event type' });
});
function requireCreatorLogin(req, res, next) {
  if (!req.session.creatorProfile) {
    return res.redirect("/auth/youtube");
  }

  next();
}

app.get("/dashboard", requireCreatorLogin, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

// ---------- Count endpoint ----------
app.get('/count/:creator', enforceRateLimit("count", 60_000, 120), (req, res) => {
  const creator = req.params.creator;

  if (!creatorStats[creator]) {
    creatorStats[creator] = {
      supports: 0,
      earnings: 0,
      videos: {},
      recentSupports: []
    };
  }

  const videos = Object.values(creatorStats[creator].videos || {});

  const topVideos = videos
    .sort((a, b) => b.supports - a.supports)
    .slice(0, 5);

  res.json({
    supports: creatorStats[creator].supports || 0,
    earnings: Number((creatorStats[creator].earnings || 0).toFixed(2)),
    recentSupports: (creatorStats[creator].recentSupports || [])
  .sort((a, b) => b.time - a.time)
  .map(attachSupporterBadges),
    topVideos
  });
});

app.post("/support/profile", enforceRateLimit("support-profile", 60 * 60 * 1000, 10), (req, res) => {
  const { anonId, name, pfp } = req.body;
  const cleanName = normalizeSupporterName(name);
  const nameError = validateSupporterName(cleanName);

  if (!anonId) {
    return res.json({ success: false, message: "Missing profile data" });
  }

  if (getSupporterLifetimeSupports(anonId) < 3) {
    return res.json({
      success: false,
      message: "Profile unlocks after 3 supports."
    });
  }

  if (nameError) {
    return res.json({ success: false, message: nameError });
  }

  supporterProfiles[anonId] = {
    name: cleanName,
    pfp: pfp || ""
  };

  Object.values(creatorStats).forEach(creator => {
    if (!creator.recentSupports) return;

    creator.recentSupports.forEach(item => {
      if (String(item.anonId) === String(anonId)) {
        item.name = cleanName || `Anonymous #${anonId || "0000"}`;
        item.pfp = pfp || "";
      }
    });
  });

  saveData();

  res.json({
    success: true,
    profile: supporterProfiles[anonId],
    badges: getSupporterBadgeCollection(anonId),
    equippedBadge: getEquippedSupporterBadge(anonId)
  });
});

app.post("/support/badge", enforceRateLimit("support-badge", 60_000, 30), (req, res) => {
  const anonId = String(req.body.anonId || "").trim();
  const badgeId = String(req.body.badgeId || "").trim();

  if (!anonId) {
    return res.json({ success: false, message: "Missing supporter." });
  }

  if (!badgeId) {
    if (supporterStats[anonId]) {
      supporterStats[anonId] = normalizeSupporterStats(supporterStats[anonId]);
      supporterStats[anonId].equippedBadgeId = "";
      saveData();
    }

    return res.json({
      success: true,
      badges: getSupporterBadgeCollection(anonId),
      equippedBadge: null
    });
  }

  const badge = getSupporterBadgeCollection(anonId).find(item => item.id === badgeId);

  if (!badge) {
    return res.json({ success: false, message: "Badge not found." });
  }

  if (!badge.unlocked) {
    return res.json({ success: false, message: "Badge is still locked." });
  }

  const stats = getOrCreateSupporterStats(anonId, getFirstSupportTime(anonId) || Date.now());
  stats.equippedBadgeId = badgeId;
  saveData();

  res.json({
    success: true,
    badges: getSupporterBadgeCollection(anonId),
    equippedBadge: getEquippedSupporterBadge(anonId)
  });
});

app.post("/support/emoji", enforceRateLimit("support-reaction", 60_000, 30), (req, res) => {
  const { creator, anonId, emoji, reactionType, stickerUrl } = req.body;
  const reaction = String(emoji || "").trim().slice(0, 80);
  const cleanStickerUrl = String(stickerUrl || "").trim();
  const isSticker = reactionType === "sticker";

  if (!creatorStats[creator] || !creatorStats[creator].recentSupports) {
    return res.json({ success: false, message: "Creator/support list not found" });
  }

  if (!reaction) {
    return res.json({ success: false, message: "Missing reaction" });
  }

  if (isSticker && cleanStickerUrl && !cleanStickerUrl.startsWith("/stickers/")) {
    return res.json({ success: false, message: "Invalid sticker" });
  }

  const supports = creatorStats[creator].recentSupports;

  const item = supports.find(s =>
    s.name === `Anonymous #${anonId}` ||
    s.name === anonId ||
    s.anonId === anonId
  );

  if (!item) {
    return res.json({ success: false, message: "Supporter not found" });
  }

  item.emoji = reaction;
  item.reactionType = isSticker ? "sticker" : "emoji";
  item.stickerUrl = isSticker ? cleanStickerUrl : "";
  saveData();

  res.json({ success: true, item: attachSupporterBadges(item) });
});

app.post("/dev/reset", requireDevAccess, enforceRateLimit("dev-reset", 60_000, 3), (req, res) => {
  userProgress = {};
  creatorStats = {};
  events = [];
  supporterProfiles = {};
  supporterStats = {};

  saveData();

  res.json({
    success: true,
    message: "Dev data reset."
  });
});

app.get("/api/me", (req, res) => {

  res.json(req.session.creatorProfile || null);

});
app.get("/api/creator/:slug", enforceRateLimit("creator-profile", 60_000, 120), (req, res) => {
  res.json(creatorProfiles[req.params.slug] || null);
});

app.get("/api/dashboard/stats", requireCreatorLogin, (req, res) => {
  const creator = req.session.creatorProfile.slug;
  const stats = creatorStats[creator] || {
    supports: 0,
    earnings: 0,
    videos: {},
    recentSupports: []
  };

  res.json({
    creator,
    supports: stats.supports || 0,
    earnings: Number((stats.earnings || 0).toFixed(2)),
    recentSupports: (stats.recentSupports || []).map(attachSupporterBadges),
    videos: stats.videos || {}
  });
});

// ---------- Creator page route ----------
app.post("/support/status", enforceRateLimit("support-status", 60_000, 60), (req, res) => {
  const { fingerprint, timeZone, creator } = req.body;

  if (!fingerprint || !timeZone) {
    return res.json({ success: false });
  }

  const deviceProgressKey = getDeviceProgressKey(req, fingerprint);
  const today = getToday(timeZone);
  const anonId = req.body.anonId;

let lifetimeSupports = getSupporterLifetimeSupports(anonId);
let creatorSupports = 0;

if (creator && creatorStats[creator]?.recentSupports) {
  creatorStats[creator].recentSupports.forEach(item => {
    if (String(item.anonId) === String(anonId)) {
      creatorSupports++;
    }
  });
}

const profile = supporterProfiles[anonId] || null;
const hasProfile = !!profile;

  const userData = userProgress[deviceProgressKey]?.days?.[today];
  lifetimeSupports = Math.max(lifetimeSupports, Number(userData?.dailyCount || 0));
const badges = getSupporterBadgeCollection(anonId, lifetimeSupports);
const equippedBadge = getEquippedSupporterBadge(anonId, lifetimeSupports);

  if (!userData) {
    return res.json({
      success: true,
      wait: 0,
      lifetimeSupports,
      creatorSupports,
      hasProfile,
      profile,
      badges,
      equippedBadge
    });
  }

  const now = Date.now();
  const remaining = COOLDOWN_MS - (now - userData.lastComplete);

  res.json({
    success: true,
    wait: remaining > 0 ? Math.ceil(remaining / 1000) : 0,
    lifetimeSupports,
    creatorSupports,
    hasProfile,
    profile,
    badges,
    equippedBadge
  });
});
app.get("/:creator", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "viewer.html"));
});

// ---------- Start server ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
