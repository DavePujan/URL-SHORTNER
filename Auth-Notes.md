# 🚀 Learning NodeJS --- Day 08, 09 & 10

### 🔐 Authentication, Authorization, Sessions & JWT

------------------------------------------------------------------------

## 🧠 Understanding Authentication & Authorization

Authentication and Authorization are two fundamental but distinct
concepts in web security.

### **Authentication (AuthN)**

*The process of verifying who you are.*

-   This is the **login** step.\
-   You provide a username and password (credentials) to prove your
    identity.\
-   **Analogy:** Showing your driver's license to a security guard to
    confirm your identity.

### **Authorization (AuthZ)**

*The process of verifying what you are allowed to do.*

-   Happens **after** authentication.\
-   Determines your access level --- e.g., regular user vs admin.\
-   **Analogy:** The security guard checks if your name has "VIP" access
    on the guest list.

------------------------------------------------------------------------

## 🔄 The Authentication Flow

1.  **User Registration** → POST request to `/register` with details
    like username & password.\
2.  **Hash Password** → Never store plain-text passwords. Use **bcrypt**
    to hash them.\
3.  **Save User** → Store the user with the hashed password in MongoDB.\
4.  **User Login** → POST request to `/login`.\
5.  **Verify User** → Match the username in the database.\
6.  **Compare Passwords** → Use bcrypt to compare input vs stored hash.\
7.  **Issue Token / Session** → If matched, generate a session cookie or
    JWT.

------------------------------------------------------------------------

## 🔑 Required Package --- `bcrypt`

`bcrypt` is used for hashing passwords securely.

``` bash
npm install bcrypt
```

------------------------------------------------------------------------

## 🧩 Example: User Model & Registration

**File:** `models/User.js`

``` js
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

// Runs before saving a new user
userSchema.pre('save', async function(next) {
    const user = this;
    if (!user.isModified('password')) return next();

    try {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(user.password, salt);
        user.password = hashedPassword;
        next();
    } catch (err) {
        return next(err);
    }
});

// Compare passwords
userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
}

const User = mongoose.model('User', userSchema);
module.exports = User;
```

------------------------------------------------------------------------

### **Register Endpoint**

**File:** `server.js`

``` js
const User = require('./models/User');

// User Registration
app.post('/register', async (req, res) => {
    try {
        const newUser = new User(req.body);
        const response = await newUser.save();
        console.log('User saved');
        res.status(201).json(response);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
```

------------------------------------------------------------------------

### **Login Endpoint**

``` js
// User Login
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });

        if (!user || !(await user.comparePassword(password))) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        console.log('User logged in');
        res.status(200).json({ message: 'Login successful' });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
```

------------------------------------------------------------------------

# 🍪 Learning NodeJS --- Day 09

## Session Cookies vs JWT Tokens

After login, we must **remember** the user.\
There are two main ways:

------------------------------------------------------------------------

### 1️⃣ **Stateful Sessions (Session Cookies)**

**How it Works:**

-   Server creates a **Session ID** and stores it with the user in DB.\
-   The browser receives it as a **cookie** and sends it with every
    request.\
-   The server validates this ID each time.

**Packages Needed:**

``` bash
npm install express-session cookie-parser
```

**✅ Pros:** - Simple and easy to revoke (delete session from DB).

**❌ Cons:** - Requires DB lookup on every request.\
- Hard to scale with multiple servers.

------------------------------------------------------------------------

### 2️⃣ **Stateless Tokens (JWT - JSON Web Token)**

**How it Works:**

-   Server generates a **JWT** with user info.\

-   Token is digitally signed using a **secret key**.\

-   Client stores token (e.g., localStorage).\

-   On future requests, client sends it via:

        Authorization: Bearer <token>

-   Server verifies and trusts the token.

**✅ Pros:** - No DB lookup (stateless).\
- Fast and scalable.

**❌ Cons:** - Cannot easily revoke before expiration.\
- Vulnerable to XSS if stored unsafely.

✅ **Preferred for APIs:** JWT

------------------------------------------------------------------------

# 🔐 Learning NodeJS --- Day 10

## JWT Token Authentication in Node.js

------------------------------------------------------------------------

### Step 1: Install Required Packages

``` bash
npm install jsonwebtoken
npm install dotenv
```

------------------------------------------------------------------------

### Step 2: Configure Environment Variables

**File:** `.env`

``` env
JWT_SECRET=mySuperSecretKey12345
```

> ⚠️ Add `.env` to `.gitignore` for security.

Load it in `server.js`:

``` js
require('dotenv').config();
const express = require('express');
```

------------------------------------------------------------------------

### Step 3: Update Login Route to Generate Token

``` js
const jwt = require('jsonwebtoken');
const User = require('./models/User');

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });

        if (!user || !(await user.comparePassword(password))) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        const payload = { id: user.id, username: user.username };
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({
            message: 'Login successful',
            token: token
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});
```

------------------------------------------------------------------------

### Step 4: Create Authentication Middleware

**File:** `middleware/authMiddleware.js`

``` js
const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Authorization header missing' });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token missing from header' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError')
            return res.status(401).json({ error: 'Token has expired' });
        if (err.name === 'JsonWebTokenError')
            return res.status(401).json({ error: 'Invalid token' });

        res.status(500).json({ error: 'Failed to authenticate token' });
    }
};

module.exports = authMiddleware;
```

------------------------------------------------------------------------

### Step 5: Protect Routes with Middleware

**File:** `server.js`

``` js
const authMiddleware = require('./middleware/authMiddleware');

// Protected GET route
app.get('/person', authMiddleware, async (req, res) => {
    try {
        console.log('User accessing /person:', req.user.username);
        const persons = await Person.find();
        res.json(persons);
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Protected POST route
app.post('/person', authMiddleware, async (req, res) => {
    // Your logic for creating a person
});
```

------------------------------------------------------------------------

## ✅ Summary

-   **AuthN** = Verify identity.\
-   **AuthZ** = Verify permissions.\
-   **bcrypt** = Secure password hashing.\
-   **JWT** = Fast, scalable, stateless authentication.\
-   **Middleware** = Protects routes & verifies tokens.

------------------------------------------------------------------------

**You now have a fully secure API!**\
🔹 Public routes → `/register`, `/login`\
🔹 Protected routes → `/person`, `/person/:id` etc.

------------------------------------------------------------------------
