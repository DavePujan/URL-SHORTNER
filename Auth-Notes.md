Learning NodeJS-DAY 08
🔐 Authentication & Authorization
Today, we'll cover one of the most critical parts of any web application: Authentication and Authorization. These two concepts are often confused but are very different.
 * Authentication (AuthN): The process of verifying who you are.
   * This is the login page. You provide a username and password (credentials) to prove your identity.
   * Analogy: Showing your driver's license to a security guard to prove your name matches the guest list.
 * Authorization (AuthZ): The process of verifying what you are allowed to do.
   * This happens after you are authenticated. Are you a regular user or an admin? Can you delete a post, or only read it?
   * Analogy: The security guard checks the "Admin" or "VIP" status on your guest list entry to see if you can enter the backstage area.
The Authentication Flow
The basic flow for adding authentication to our restaurant API is:
 * User Registration: A user sends a POST request to /register with their details (e.g., username, password).
 * Hash Password: We NEVER store passwords in plain text. We use a library like bcrypt to "hash" the password—a one-way process that turns the password into a long, secure string.
 * Save User: We save the new user in our MongoDB database, storing the hashed password.
 * User Login: A user sends a POST request to /login with their username and password.
 * Verify User: We find the user in the database by their username.
 * Compare Password: We use bcrypt to compare the password they just sent with the hashed password stored in our database.
 * Issue Token/Session: If the passwords match, the user is authenticated! We now need a way to "remember" them for future requests. We do this by giving them either a session cookie or a JSON Web Token (JWT).
🔑 Required Package: bcrypt
This is the industry-standard package for hashing passwords. It's slow on purpose, which makes it very difficult for attackers to "brute-force" (guess) passwords.
npm install bcrypt

Example: User Model & Registration
Let's update our code. First, we'll create a User model.
models/User.js
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    }
});

// This function will run *before* a new user is saved
userSchema.pre('save', async function(next) {
    const user = this;

    // Only hash the password if it has been modified (or is new)
    if (!user.isModified('password')) return next();

    try {
        // Generate a "salt" - a random string to make the hash unique
        const salt = await bcrypt.genSalt(10);
        
        // Hash the password with the salt
        const hashedPassword = await bcrypt.hash(user.password, salt);
        
        // Replace the plain-text password with the hashed password
        user.password = hashedPassword;
        next();
    } catch (err) {
        return next(err);
    }
});

// Add a method to our user model to compare passwords
userSchema.methods.comparePassword = async function(candidatePassword) {
    try {
        // Use bcrypt to compare the provided password with the stored hash
        const isMatch = await bcrypt.compare(candidatePassword, this.password);
        return isMatch;
    } catch (err) {
        throw err;
    }
}

const User = mongoose.model('User', userSchema);
module.exports = User;

Now, let's create a /register endpoint in our server file.
server.js
// ... (imports for express, bodyParser, db connection)
const User = require('./models/User');

// User Registration
app.post('/register', async (req, res) => {
    try {
        const data = req.body;
        const newUser = new User(data);
        const response = await newUser.save();
        console.log('User saved');
        res.status(201).json(response);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// User Login
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find the user by username
        const user = await User.findOne({ username: username });

        // If user doesn't exist or password doesn't match, return error
        if (!user || !(await user.comparePassword(password))) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        // --- AUTHENTICATION SUCCESSFUL ---
        // Now, we will issue a token (covered in the next section)
        console.log('User logged in');
        res.status(200).json({ message: 'Login successful' });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

Learning NodeJS-DAY 09
🍪 Session Cookies vs. Tokens (JWT)
After a user logs in, we need to remember them. There are two main ways to do this: Stateful Sessions (with cookies) and Stateless Tokens (with JWT).
1. Stateful Sessions (Session Cookies)
This is the traditional method.
 * How it works:
   * User logs in.
   * The server creates a unique, random Session ID (e.g., abc123xyz).
   * The server stores this Session ID in its own database, linking it to the user's ID (e.g., {"session_id": "abc123xyz", "user_id": "60f..."}). This is "stateful" because the server must store the session state.
   * The server sends this Session ID back to the client as a cookie.
   * The browser automatically attaches this cookie to every future request to our server.
   * When a request comes in, the server reads the Session ID from the cookie, looks it up in its session database, finds the matching user, and knows who is making the request.
 * Packages needed: express-session and cookie-parser
 * Pros:
   * Simple to use.
   * Can be revoked easily: To log a user out, you just delete their session from your database.
 * Cons:
   * Requires a database lookup on every request to validate the session.
   * Doesn't scale well: If you have many servers (load balancing), they all need to access the same session database.
2. Stateless Tokens (JSON Web Tokens - JWT)
This is the modern, "stateless" method, perfect for APIs.
 * How it works:
   * User logs in.
   * The server creates a JSON Web Token (JWT). This token is a long string that is not random. It's a JSON object containing the user's ID, which is then digitally signed using a secret key.
   * The server does not store the token. This is "stateless" because all the information is in the token itself.
   * The server sends this token back to the client.
   * The client is responsible for storing the token (e.g., in localStorage).
   * For future requests, the client must manually attach the token in the Authorization header (e.g., Authorization: Bearer <token>).
   * When a request comes in, the server reads the token from the header, verifies the signature using its secret key, and trusts the data inside (e.g., the user_id).
 * Pros:
   * Stateless: No database lookup needed to verify the token. This is very fast.
   * Scales perfectly: Any server can verify the token as long as it has the secret key.
 * Cons:
   * Cannot be easily revoked: A token is valid until it expires. If a token is stolen, it can be used until its expiration time.
   * Client-side storage (localStorage) can be vulnerable to XSS attacks.
For our API, JWT is the preferred choice.
Learning NodeJS-DAY 10
🚀 JWT Token Authentication in Node.js
Let's implement JWT authentication for our login endpoint.
1. Install jsonwebtoken
This package helps us create and verify tokens.
npm install jsonwebtoken

2. Install dotenv
We need to store our secret key securely. We never write secrets directly in our code. We use environment variables. dotenv helps us manage this.
npm install dotenv

Create a new file named .env in your root folder. This file should be added to your .gitignore!
.env
# This is a secret string only your server knows. Make it long and random.
JWT_SECRET=mySuperSecretKey12345

Now, load this file at the very top of your server.js.
server.js
require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
// ... rest of your file

3. Update the Login Endpoint to Generate a Token
Let's modify our /login route from DAY 08.
server.js
// ... (imports)
const jwt = require('jsonwebtoken');
const User = require('./models/User');

// ... (app.use(bodyParser.json()), etc.)

// ... (/register endpoint)

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username: username });

        if (!user || !(await user.comparePassword(password))) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        // --- Generate JWT Token ---
        // The "payload" is the data we want to store in the token
        const payload = {
            id: user.id,
            username: user.username
            // You can add more data, but keep it light
            // DO NOT put sensitive data like passwords here
        }
        
        // Sign the token with our secret key
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '1h' }); // Token expires in 1 hour

        // Send the token back to the client
        res.status(200).json({
            message: 'Login successful',
            token: token
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

4. Create Middleware to Verify the Token
Now, how do we protect routes like GET /person? We need middleware.
Middleware is just a function that runs before our main route handler. This middleware will check for a valid token.
Let's create a new file for our middleware.
middleware/authMiddleware.js
const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
    // 1. Check if the Authorization header exists
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ error: 'Authorization header missing' });
    }

    // 2. Extract the token from the header
    // The header format is "Bearer <token>"
    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'Token missing from header' });
    }

    try {
        // 3. Verify the token
        // This checks if the token is valid and hasn't expired
        const decodedPayload = jwt.verify(token, process.env.JWT_SECRET);

        // 4. Attach the user's data to the request object
        // Now all our protected routes will know *who* the user is
        req.user = decodedPayload;
        
        // 5. Call 'next()' to proceed to the actual route handler
        next();

    } catch (err) {
        console.error(err);
        // Handle different errors
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token has expired' });
        }
        if (err.name === 'JsonWebTokenError') {
            return res.status(401).json({ error: 'Invalid token' });
        }
        res.status(500).json({ error: 'Failed to authenticate token' });
    }
}

module.exports = authMiddleware;

5. Use the Middleware to Protect Routes
Now, we just add this middleware to any route we want to protect.
server.js
// ... (imports)
const authMiddleware = require('./middleware/authMiddleware');

// ... (db connection, login/register routes)

// --- PROTECTED ROUTES ---

// Now, only users with a valid token can access the /person route
// The authMiddleware will run first. If it calls next(), the async (req, res) handler will run.
// If it sends a response (e.g., 401 error), the handler will *not* run.
app.get('/person', authMiddleware, async (req, res) => {
    try {
        // Thanks to our middleware, req.user is available!
        console.log('User accessing /person:', req.user.username);
        
        const persons = await Person.find();
        res.json(persons);
    } catch (error) {
        console.error('Error fetching persons:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// We can also protect our POST, PUT, DELETE methods
app.post('/person', authMiddleware, async (req, res) => {
    // ... (logic to create a person)
});

Now you have a fully secured API. Unauthenticated users can only access /register and /login, while authenticated users (who provide a valid JWT) can access the /person routes.
