const express = require('express');
const helmet = require('helmet');
const winston = require('winston');
const bcrypt = require('bcrypt');
const validator = require('validator');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const path = require('path');
const cors = require('cors');
// NEW: Week 5 Dependencies
const sqlite3 = require('sqlite3').verbose();
const cookieParser = require('cookie-parser');
const csurf = require('csurf');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your-super-secret-key-change-in-production';

// --- 1. WEEK 5: DATABASE SETUP (SQLite) ---
// This creates a physical 'users.db' file in your folder
const db = new sqlite3.Database('./users.db', (err) => {
    if (err) {
        console.error('Error opening database', err);
    } else {
        // Create the users table if it doesn't exist
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT UNIQUE,
            password TEXT
        )`);
    }
});

// --- 2. MIDDLEWARE & SECURITY HEADERS ---
app.use(express.json());
app.use(express.static('public')); 
app.use(cookieParser()); // NEW: Required for CSRF

// CORS Configuration
app.use(cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:3000'], 
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key', 'csrf-token']
}));

// Helmet Security Headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"], 
            styleSrc: ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            upgradeInsecureRequests: [],
        },
    },
    hsts: {
        maxAge: 31536000, 
        includeSubDomains: true,
        preload: true
    }
}));

// NEW: CSRF Protection Middleware
// This ensures no external site can forge requests to your server
const csrfProtection = csurf({ cookie: true });

// --- 3. LOGGER SETUP (Winston) ---
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'security.log' })
    ]
});

// --- 4. RATE LIMITING ---
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 5, 
    message: { error: 'Too many attempts. Please try again in 15 minutes.' },
    handler: (req, res, next, options) => {
        logger.warn(`[BRUTE-FORCE] attempt blocked from IP: ${req.ip}`);
        res.status(options.statusCode).json(options.message);
    }
});

const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;

// --- 5. ROUTES ---

// NEW: CSRF Token Endpoint
// The frontend will call this to get a token before submitting any forms
app.get('/api/csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Secure API Endpoint (API Key)
const VALID_API_KEY = 'intern-super-secret-api-key-2026'; 
app.get('/api/sensitive-data', (req, res) => {
    const providedKey = req.headers['x-api-key'];
    if (!providedKey || providedKey !== VALID_API_KEY) {
        logger.warn(`[API-ALERT] Unauthorized access attempt to /api/sensitive-data from IP: ${req.ip}`);
        return res.status(401).json({ error: 'Unauthorized: Invalid API Key' });
    }
    logger.info(`[API-SUCCESS] Authorized access from IP: ${req.ip}`);
    res.json({ 
        status: "Success",
        message: "You have securely accessed the restricted API endpoint.", 
        classified_data: ["Project Phoenix Status: Active", "Internal DB IP: 10.0.0.54", "Vault Access Code: 8847-B"] 
    });
});

// REGISTER (Upgraded with Prepared Statements & CSRF)
app.post('/register', csrfProtection, authLimiter, async (req, res) => {
    const { username, email, password, confirmPassword } = req.body;

    if (!username || !validator.isAlphanumeric(username)) {
        return res.status(400).json({ error: 'Username must be alphanumeric.' });
    }
    if (!validator.isEmail(email)) {
        return res.status(400).json({ error: 'Please enter a valid email address.' });
    }
    if (password !== confirmPassword) {
        return res.status(400).json({ error: 'Passwords do not match.' });
    }
    if (!strongPasswordRegex.test(password)) {
        return res.status(400).json({ error: 'Password must be 8+ chars with uppercase, lowercase, number, and a special char.' });
    }

    // UPGRADED: Checking for duplicates securely using Prepared Statements (?)
    db.get('SELECT * FROM users WHERE email = ? OR username = ?', [email, username], async (err, row) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (row) {
            logger.warn(`Registration blocked: Duplicate user attempted (${username} / ${email})`);
            return res.status(400).json({ error: 'Username or Email already exists.' });
        }

        try {
            const hashedPassword = await bcrypt.hash(password, 10);
            
            // UPGRADED: Inserting data securely using Prepared Statements (?)
            db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hashedPassword], (err) => {
                if (err) return res.status(500).json({ error: 'Failed to register user' });
                
                logger.info(`New user registered: ${username} (${email})`);
                res.status(201).json({ message: 'Registration successful! You can now log in.' });
            });
        } catch (error) {
            logger.error('Registration error', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    });
});

// LOGIN (Upgraded with Prepared Statements & CSRF)
app.post('/login', csrfProtection, authLimiter, (req, res) => {
    const { email, password } = req.body;

    // UPGRADED: Fetching user securely using Prepared Statements (?)
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        
        if (!user) {
            logger.warn(`Login failed: Unregistered email (${email})`);
            return res.status(400).json({ error: 'Invalid email or password.' });
        }

        try {
            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                logger.warn(`Login failed: Incorrect password for ${email}`);
                return res.status(400).json({ error: 'Invalid email or password.' });
            }

            const token = jwt.sign({ username: user.username, email: user.email }, SECRET_KEY, { expiresIn: '1h' });
            
            logger.info(`User logged in successfully: ${user.username}`);
            res.json({ message: `Welcome securely, ${user.username}!`, token: token, username: user.username });
        } catch (error) {
            logger.error('Login error', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    });
});

// FORGOT PASSWORD (Upgraded with Prepared Statements & CSRF)
app.post('/forgot-password', csrfProtection, authLimiter, (req, res) => {
    const { username, email, newPassword } = req.body;

    if (!strongPasswordRegex.test(newPassword)) {
        return res.status(400).json({ error: 'New password must meet complexity requirements.' });
    }

    db.get('SELECT * FROM users WHERE email = ? AND username = ?', [email, username], async (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        
        if (!user) {
            logger.warn(`Password reset failed: No match for Username: ${username}, Email: ${email}`);
            return res.status(400).json({ error: 'No account found matching that username and email.' });
        }

        try {
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            
            // UPGRADED: Updating password securely
            db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, user.id], (err) => {
                if (err) return res.status(500).json({ error: 'Failed to reset password' });
                
                logger.info(`Password successfully reset for user: ${username}`);
                res.json({ message: 'Password has been successfully reset. You may now log in.' });
            });
        } catch (error) {
            logger.error('Password reset error', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    });
});

app.listen(PORT, () => {
    logger.info(`Premium Secure Server running at http://localhost:${PORT}`);
    console.log(`Premium Secure Server running at http://localhost:${PORT}`);
});
