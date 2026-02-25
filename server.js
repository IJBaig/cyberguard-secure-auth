const express = require('express');
const helmet = require('helmet');
const winston = require('winston');
const bcrypt = require('bcrypt');
const validator = require('validator');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your-super-secret-key-change-in-production'; // Used to sign JWTs

// --- 1. MIDDLEWARE & SECURITY HEADERS ---
app.use(express.json());
app.use(express.static('public')); // Serves the frontend HTML
app.use(helmet()); // Automatically sets secure HTTP headers

// --- 2. LOGGER SETUP (Winston) ---
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

logger.info('Secure application started on port 3000');

// --- 3. BRUTE FORCE PROTECTION (Rate Limiting) ---
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 requests per window
    message: { error: 'Too many attempts. Please try again in 15 minutes.' },
    handler: (req, res, next, options) => {
        logger.warn(`Brute force attempt blocked from IP: ${req.ip}`);
        res.status(options.statusCode).json(options.message);
    }
});

// In-memory array to act as our database (Resets when server restarts)
const usersDatabase = [];

// Password Complexity Regex: Min 8 chars, 1 uppercase, 1 lowercase, 1 number, 1 special character
const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$/;

// --- 4. ROUTES ---

// REGISTER
app.post('/register', authLimiter, async (req, res) => {
    const { username, email, password, confirmPassword } = req.body;

    // Strict Validation
    if (!username || !validator.isAlphanumeric(username)) {
        return res.status(400).json({ error: 'Username must be alphanumeric.' });
    }
    if (!validator.isEmail(email)) {
        logger.warn(`Registration blocked: Invalid email format (${email})`);
        return res.status(400).json({ error: 'Please enter a valid email address.' });
    }
    if (password !== confirmPassword) {
        return res.status(400).json({ error: 'Passwords do not match.' });
    }
    if (!strongPasswordRegex.test(password)) {
        return res.status(400).json({ error: 'Password must be 8+ chars with uppercase, lowercase, number, and special char.' });
    }

    // Duplicate Check
    if (usersDatabase.find(u => u.email === email || u.username === username)) {
        logger.warn(`Registration blocked: Duplicate user attempted (${username} / ${email})`);
        return res.status(400).json({ error: 'Username or Email already exists.' });
    }

    try {
        // Hash and Save
        const hashedPassword = await bcrypt.hash(password, 10);
        usersDatabase.push({ username, email, password: hashedPassword });
        
        logger.info(`New user registered: ${username} (${email})`);
        res.status(201).json({ message: 'Registration successful! You can now log in.' });
    } catch (error) {
        logger.error('Registration error', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// LOGIN
app.post('/login', authLimiter, async (req, res) => {
    const { email, password } = req.body;

    const user = usersDatabase.find(u => u.email === email);
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

        // Generate JWT Token
        const token = jwt.sign({ username: user.username, email: user.email }, SECRET_KEY, { expiresIn: '1h' });
        
        logger.info(`User logged in successfully: ${user.username}`);
        res.json({ message: `Welcome securely, ${user.username}!`, token: token, username: user.username });
    } catch (error) {
        logger.error('Login error', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// FORGOT PASSWORD
app.post('/forgot-password', authLimiter, async (req, res) => {
    const { username, email, newPassword } = req.body;

    if (!strongPasswordRegex.test(newPassword)) {
        return res.status(400).json({ error: 'New password must meet complexity requirements.' });
    }

    // Require both Username and Email for a password reset
    const userIndex = usersDatabase.findIndex(u => u.email === email && u.username === username);
    
    if (userIndex === -1) {
        logger.warn(`Password reset failed: No match for Username: ${username}, Email: ${email}`);
        return res.status(400).json({ error: 'No account found matching that username and email.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        usersDatabase[userIndex].password = hashedPassword;
        
        logger.info(`Password successfully reset for user: ${username}`);
        res.json({ message: 'Password has been successfully reset. You may now log in.' });
    } catch (error) {
        logger.error('Password reset error', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.listen(PORT, () => {
    console.log(`Premium Secure Server running at http://localhost:${PORT}`);
});
