# 🚀 Full-Stack Guide: URL Shortener (Node.js + React.js)

This guide walks you through building a complete **full-stack URL shortener** application. It includes:

- **Node.js & Express API (Backend):** Manages users, authentication, and link shortening (with MongoDB).
- **React.js (Front-End):** Lets users register, log in, shorten URLs, and view their list.

This setup uses **manual JWT + bcrypt authentication** (not Passport.js).

---

## 🧩 Part 1: Backend Project Setup

```bash
# Create a new folder for the backend
mkdir url-shortener-api
cd url-shortener-api

# Initialize Node.js
npm init -y

# Install dependencies
npm install express mongoose body-parser dotenv bcrypt jsonwebtoken cors
```

---

## ⚙️ Part 2: Backend Database Connection (`db.js`)

```js
const mongoose = require('mongoose');
require('dotenv').config();

const mongoURL = process.env.MONGODB_URL;

mongoose.connect(mongoURL, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const db = mongoose.connection;

db.on('connected', () => console.log('Connected to MongoDB'));
db.on('error', err => console.error('MongoDB error:', err));
db.on('disconnected', () => console.log('MongoDB disconnected'));

module.exports = db;
```

**.env**
```env
MONGODB_URL=mongodb://localhost:27017/urlshortener
JWT_SECRET=mySuperRandomSecretKey123
```

---

## 👤 Part 3: Backend User Model (`models/User.js`)

```js
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);
```

---

## 🔒 Part 4: Auth Middleware (`middleware/authMiddleware.js`)

```js
const jwt = require('jsonwebtoken');
require('dotenv').config();

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Authorization header missing' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token missing' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

module.exports = authMiddleware;
```

---

## 🔗 Part 5: URL Shortener Model (`models/Url.js`)

```js
const mongoose = require('mongoose');

const urlSchema = new mongoose.Schema({
  originalUrl: { type: String, required: true },
  shortCode: { type: String, required: true, unique: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Url', urlSchema);
```

---

## 🧠 Part 6: Backend Main Server (`server.js`)

```js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const db = require('./db');
const jwt = require('jsonwebtoken');

const User = require('./models/User');
const Url = require('./models/Url');
const authMiddleware = require('./middleware/authMiddleware');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;

// Register
app.post('/register', async (req, res) => {
  try {
    const user = new User(req.body);
    const response = await user.save();
    const token = jwt.sign({ id: response.id, username: response.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.status(201).json({ response, token });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user || !(await user.comparePassword(password)))
    return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.status(200).json({ message: 'Login successful', token });
});

// Shorten URL
app.post('/api/shorten', authMiddleware, async (req, res) => {
  const { originalUrl, shortCode } = req.body;
  const existing = await Url.findOne({ shortCode });
  if (existing) return res.status(400).json({ error: 'Short code already in use' });

  const newUrl = new Url({ originalUrl, shortCode, user: req.user.id });
  const savedUrl = await newUrl.save();
  res.status(201).json(savedUrl);
});

// My URLs
app.get('/api/my-urls', authMiddleware, async (req, res) => {
  const urls = await Url.find({ user: req.user.id });
  res.status(200).json(urls);
});

// Redirect
app.get('/:shortCode', async (req, res) => {
  const url = await Url.findOne({ shortCode: req.params.shortCode });
  if (url) return res.redirect(url.originalUrl);
  res.status(404).json({ error: 'URL not found' });
});

app.listen(PORT, () => console.log(`Backend running on port ${PORT}`));
```

---

## 🧪 Part 7: How to Use Backend API

1. Run the backend:
   ```bash
   node server.js
   ```
   → **http://localhost:3000**

2. Register/Login to get a token.  
3. Use the token in the `Authorization` header for `/api/shorten` and `/api/my-urls`.

---

## 💻 Part 8: Front-End (React.js)

### 8.1 Setup

```bash
npx create-react-app url-shortener-client
cd url-shortener-client
npm install axios
```

### 8.2 API Client (`src/api.js`)

```js
import axios from 'axios';

const api = axios.create({ baseURL: 'http://localhost:3000' });

api.interceptors.request.use(config => {
  const token = localStorage.getItem('token');
  if (token) config.headers['Authorization'] = `Bearer ${token}`;
  return config;
});

export default api;
```

### 8.3 Main App (`src/App.js`)

```js
import React, { useState, useEffect } from 'react';
import AuthPage from './components/AuthPage';
import ShortenerPage from './components/ShortenerPage';
import './App.css';

function App() {
  const [token, setToken] = useState(localStorage.getItem('token') || '');

  const handleLogin = (t) => { localStorage.setItem('token', t); setToken(t); };
  const handleLogout = () => { localStorage.removeItem('token'); setToken(''); };

  return (
    <div className="App">
      <header className="App-header">
        <h1>URL Shortener</h1>
        {token ? <ShortenerPage onLogout={handleLogout} /> : <AuthPage onLogin={handleLogin} />}
      </header>
    </div>
  );
}

export default App;
```

### 8.4 Auth Component (`src/components/AuthPage.js`)

```js
import React, { useState } from 'react';
import api from '../api';

function AuthPage({ onLogin }) {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    const endpoint = isLogin ? '/login' : '/register';
    try {
      const res = await api.post(endpoint, { username, password });
      if (res.data.token) onLogin(res.data.token);
    } catch (err) {
      setError(err.response?.data?.error || 'Error occurred');
    }
  };

  return (
    <div>
      <h2>{isLogin ? 'Login' : 'Register'}</h2>
      <form onSubmit={handleSubmit}>
        <input value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Username" required />
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" required />
        <button type="submit">{isLogin ? 'Login' : 'Register'}</button>
      </form>
      <button onClick={() => setIsLogin(!isLogin)}>
        {isLogin ? 'Need to register?' : 'Have an account? Login'}
      </button>
      {error && <p style={{ color: 'red' }}>{error}</p>}
    </div>
  );
}

export default AuthPage;
```

### 8.5 Shortener Component (`src/components/ShortenerPage.js`)

```js
import React, { useState, useEffect } from 'react';
import api from '../api';

function ShortenerPage({ onLogout }) {
  const [originalUrl, setOriginalUrl] = useState('');
  const [shortCode, setShortCode] = useState('');
  const [urls, setUrls] = useState([]);
  const [error, setError] = useState('');

  const fetchUrls = async () => {
    try {
      const res = await api.get('/api/my-urls');
      setUrls(res.data);
    } catch {
      setError('Failed to fetch URLs');
    }
  };

  useEffect(() => { fetchUrls(); }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    try {
      await api.post('/api/shorten', { originalUrl, shortCode });
      setOriginalUrl('');
      setShortCode('');
      fetchUrls();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to shorten');
    }
  };

  return (
    <div>
      <button onClick={onLogout} style={{ float: 'right' }}>Logout</button>
      <h3>Create a Short Link</h3>
      <form onSubmit={handleSubmit}>
        <input placeholder="Original URL" value={originalUrl} onChange={e => setOriginalUrl(e.target.value)} required />
        <input placeholder="Short Code" value={shortCode} onChange={e => setShortCode(e.target.value)} required />
        <button type="submit">Shorten</button>
      </form>
      {error && <p style={{ color: 'red' }}>{error}</p>}
      <hr />
      <h3>My Links</h3>
      <ul>
        {urls.map(u => (
          <li key={u._id}>
            <a href={`http://localhost:3000/${u.shortCode}`} target="_blank" rel="noopener noreferrer">
              {`http://localhost:3000/${u.shortCode}`}
            </a>
            <p>{u.originalUrl}</p>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default ShortenerPage;
```

### 8.6 Styling (`src/App.css`)

```css
.App { text-align: center; }
.App-header { background: #282c34; min-height: 100vh; display: flex; flex-direction: column; align-items: center; justify-content: center; color: white; }
input, button { margin: 5px; padding: 8px; font-size: 1rem; }
button { background: #61dafb; border: none; border-radius: 4px; cursor: pointer; }
li { list-style: none; background: #3a3f4a; color: #fff; margin: 10px; padding: 10px; border-radius: 6px; width: 500px; }
li a { color: #61dafb; font-weight: bold; }
```

---

## 🧭 Part 9: Run the Full Stack App

**Terminal 1: Backend**
```bash
cd url-shortener-api
node server.js
```

**Terminal 2: Frontend**
```bash
cd url-shortener-client
npm start
```

Your app will run at **http://localhost:3001** (frontend) and connect to **http://localhost:3000** (backend).

---
✅ You can now **register, log in, shorten URLs, and view them instantly!**
