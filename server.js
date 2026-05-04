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


const app = express();

app.use(session({
  secret: "change-this-secret-later",
  resave: false,
  saveUninitialized: false
}));

app.use(bodyParser.json());
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
    profileImage: channel.snippet.thumbnails.high.url
  };

  creatorProfiles[creatorProfile.slug] = creatorProfile;

res.redirect("/" + creatorProfile.slug);
});



// ---------- Data storage ----------
let events = []; // simple in-memory log (replace with DB in production)
let userProgress = {};
let creatorStats = {};
let creatorProfiles = {};

try {
  const data = JSON.parse(fs.readFileSync('data.json', 'utf8'));
  userProgress = data.userProgress || {};
  creatorStats = data.creatorStats || {};
  events = data.events || [];
} catch (err) {
  console.log('No data file found, starting fresh');
}

// ---------- Helpers ----------
function hashFingerprint(fingerprintString) {
  return crypto.createHash('sha256').update(fingerprintString).digest('hex');
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

function saveData() {
  fs.writeFileSync(
    'data.json',
    JSON.stringify(
      {
        userProgress,
        creatorStats,
        events
      },
      null,
      2
    )
  );
}

// ---------- Config ----------
const MAX_SUPPORTS_PER_DAY = 300;
const COOLDOWN_MS = 30_000; // 30 seconds
const REWARD_PER_SUPPORT = 0.05;
const MIN_AD_WATCH_MS = 14_000; // basic backend validation

// ---------- Event endpoint ----------
app.post('/event', (req, res) => {
  const { type, creator, fingerprint, timeZone } = req.body;

  if (!type || !creator || !fingerprint || !timeZone) {
    return res.json({ success: false, message: 'Missing data' });
  }

  const fpHash = hashFingerprint(fingerprint);
  const today = getToday(timeZone);
  const now = Date.now();

  // init user root if first time
  if (!userProgress[fpHash]) {
    userProgress[fpHash] = {
      timeZone,
      days: {}
    };
  }

  // lock timezone to this fingerprint
  if (!userProgress[fpHash].timeZone) {
    userProgress[fpHash].timeZone = timeZone;
  }

  if (userProgress[fpHash].timeZone !== timeZone) {
    return res.json({ success: false, message: 'Timezone mismatch' });
  }

  // init daily bucket
  if (!userProgress[fpHash].days[today]) {
    userProgress[fpHash].days[today] = {
      dailyCount: 0,
      lastComplete: 0,
      adStartTime: 0
    };
  }

  const userData = userProgress[fpHash].days[today];

  // ---------- Anti-bot / self-support ----------
  if (fpHash === hashFingerprint(creator)) {
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
      creatorStats[creator] = { supports: 0, earnings: 0 };
    }

    creatorStats[creator].supports++;
    creatorStats[creator].earnings += REWARD_PER_SUPPORT;

    // log event once
    events.push({
      timestamp: now,
      creator,
      fingerprint: fpHash,
      type: 'support_complete',
      timeZone
    });

    saveData();

    return res.json({
      success: true,
      supports: creatorStats[creator].supports,
      earnings: Number(creatorStats[creator].earnings.toFixed(2))
    });
  }

  return res.json({ success: false, message: 'Unknown event type' });
});

// ---------- Count endpoint ----------
app.get('/count/:creator', (req, res) => {
  const creator = req.params.creator;

  if (!creatorStats[creator]) {
    creatorStats[creator] = { supports: 0, earnings: 0 };
  }

  res.json({
    count: creatorStats[creator].supports,
    earnings: Number(creatorStats[creator].earnings.toFixed(2))
  });
});

app.get("/api/me", (req, res) => {

  res.json(req.session.creatorProfile || null);

});
app.get("/api/creator/:slug", (req, res) => {
  res.json(creatorProfiles[req.params.slug] || null);
});

// ---------- Creator page route ----------
app.get('/:creator', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ---------- Start server ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));