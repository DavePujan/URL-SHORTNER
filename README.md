# 🔗 SnapLink — Smart URL Shortener

A fully functional, production-ready URL shortener with a beautiful dark UI, JWT authentication, click tracking, QR codes, and custom aliases.

## ✨ Features

- **URL Shortening** — Instantly create short links with auto-generated or custom codes
- **Click Analytics** — Track every click with timestamps and referrer info
- **QR Code Generation** — Instant QR code for every short link
- **Copy to Clipboard** — One-click copy with visual feedback
- **JWT Authentication** — Secure register/login with 7-day sessions
- **Dashboard** — Manage all your links in one beautiful view
- **Delete Links** — Remove links you no longer need
- **Stats** — Total links, total clicks, average clicks per link
- **File-based DB** — Zero external dependencies (no MongoDB needed!)

## 🛠 Tech Stack

| Layer | Tech |
|-------|------|
| Backend | Node.js + Express 5 |
| Auth | JWT + bcrypt |
| Database | lowdb (JSON file) |
| Frontend | React + Vite |
| QR Codes | qrcode.react |
| HTTP Client | axios |

## 🚀 Quick Start

### 1. Install Dependencies
```bash
npm --prefix backend install
npm --prefix frontend install
```

### 2. Configure Backend
```bash
cp backend/.env.example backend/.env
# Edit backend/.env with your settings
```

### 3. Start Development

**Terminal 1 — Backend:**
```bash
node backend/server.js
# → http://localhost:3001
```

**Terminal 2 — Frontend:**
```bash
npm --prefix frontend run dev
# → http://localhost:5173
```

Or use the production build (frontend served by backend):
```bash
npm --prefix frontend run build
node backend/server.js
# → http://localhost:3001 (serves full app)
```

## 🔌 API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/register` | ❌ | Create account |
| POST | `/auth/login` | ❌ | Get JWT token |
| POST | `/api/shorten` | ✅ | Create short link |
| GET | `/api/my-urls` | ✅ | List your links |
| DELETE | `/api/urls/:id` | ✅ | Delete a link |
| GET | `/api/stats` | ✅ | Dashboard stats |
| GET | `/:shortCode` | ❌ | Redirect to original URL |

## 📁 Project Structure

```
URL-SHORTNER/
├── backend/
│   ├── middleware/
│   │   └── authMiddleware.js
│   ├── server.js          # Express API
│   ├── db.js              # lowdb setup
│   ├── .env               # Environment variables
│   └── package.json
├── frontend/
│   ├── src/
│   │   ├── context/AuthContext.jsx
│   │   ├── pages/
│   │   │   ├── AuthPage.jsx
│   │   │   └── Dashboard.jsx
│   │   ├── components/
│   │   │   └── UrlCard.jsx
│   │   ├── api.js
│   │   ├── App.jsx
│   │   └── index.css
│   └── package.json
└── README.md
```
