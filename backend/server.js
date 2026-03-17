require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const { nanoid } = require('nanoid');
const { randomUUID } = require('crypto');
const db = require('./db');
const authMiddleware = require('./middleware/authMiddleware');

const app = express();
const PORT = process.env.PORT || 3001;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

app.use(cors());
app.use(express.json());

// ─── Rate Limiters ───────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const redirectLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 60,
  message: { error: 'Too many redirect requests.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ─── Serve built frontend (static files) ────────────────────────────────────
const frontendDist = path.join(__dirname, '../frontend/dist');
if (fs.existsSync(frontendDist)) {
  app.use(express.static(frontendDist));
}

// ─── Auth Routes ─────────────────────────────────────────────────────────────

// Register
app.post('/auth/register', authLimiter, async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password)
    return res.status(400).json({ error: 'All fields are required' });

  const existingUser = db.get('users').find({ username }).value();
  const existingEmail = db.get('users').find({ email }).value();
  if (existingUser || existingEmail)
    return res.status(409).json({ error: 'Username or email already exists' });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = {
      id: randomUUID(),
      username,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString(),
    };
    db.get('users').push(user).write();

    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: { id: user.id, username: user.username, email: user.email } });
  } catch {
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/auth/login', authLimiter, async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });

  const user = db.get('users').find({ username }).value();
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
});

// ─── URL Routes ───────────────────────────────────────────────────────────────

// Shorten URL
app.post('/api/shorten', apiLimiter, authMiddleware, (req, res) => {
  const { originalUrl, customCode } = req.body;
  if (!originalUrl) return res.status(400).json({ error: 'Original URL is required' });

  try { new URL(originalUrl); } catch {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  const shortCode = customCode ? customCode.trim().toLowerCase() : nanoid(6);
  const existing = db.get('urls').find({ shortCode }).value();
  if (existing) return res.status(409).json({ error: 'Short code already in use. Try another.' });

  const urlEntry = {
    id: randomUUID(),
    originalUrl,
    shortCode,
    shortUrl: `${BASE_URL}/${shortCode}`,
    userId: req.user.id,
    clicks: 0,
    clickHistory: [],
    createdAt: new Date().toISOString(),
  };

  db.get('urls').push(urlEntry).write();
  res.status(201).json(urlEntry);
});

// Get my URLs
app.get('/api/my-urls', apiLimiter, authMiddleware, (req, res) => {
  const urls = db.get('urls').filter({ userId: req.user.id }).value();
  res.json(urls.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)));
});

// Delete URL
app.delete('/api/urls/:id', apiLimiter, authMiddleware, (req, res) => {
  const urlEntry = db.get('urls').find({ id: req.params.id, userId: req.user.id }).value();
  if (!urlEntry) return res.status(404).json({ error: 'URL not found' });
  db.get('urls').remove({ id: req.params.id }).write();
  res.json({ message: 'Deleted successfully' });
});

// Dashboard stats
app.get('/api/stats', apiLimiter, authMiddleware, (req, res) => {
  const urls = db.get('urls').filter({ userId: req.user.id }).value();
  const totalLinks = urls.length;
  const totalClicks = urls.reduce((sum, u) => sum + (u.clicks || 0), 0);
  res.json({ totalLinks, totalClicks });
});

// ─── Redirect Route ───────────────────────────────────────────────────────────
app.get('/:shortCode', redirectLimiter, (req, res, next) => {
  const { shortCode } = req.params;
  // Skip if looks like a static asset request
  if (shortCode.includes('.')) return next();

  const urlEntry = db.get('urls').find({ shortCode }).value();
  if (!urlEntry) return next();

  // Track click
  const clickRecord = {
    timestamp: new Date().toISOString(),
    referer: req.headers.referer || 'direct',
    userAgent: req.headers['user-agent'] || '',
  };
  db.get('urls')
    .find({ shortCode })
    .assign({
      clicks: (urlEntry.clicks || 0) + 1,
      clickHistory: [...(urlEntry.clickHistory || []).slice(-99), clickRecord],
    })
    .write();

  res.redirect(302, urlEntry.originalUrl);
});

// SPA fallback - serve index.html for all other routes (when built frontend exists)
if (fs.existsSync(frontendDist)) {
  app.get('/{*path}', apiLimiter, (req, res) => {
    res.sendFile(path.join(frontendDist, 'index.html'));
  });
}

app.listen(PORT, () => console.log(`🚀 SnapLink running on http://localhost:${PORT}`));
