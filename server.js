const express = require('express');
const helmet = require('helmet');
const winston = require('winston');
const bcrypt = require('bcrypt');
const validator = require('validator');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your-super-secret-key'; // Used for JWT tokens

// --- 1. MIDDLEWARE ---
app.use(express.json()); // Parses incoming JSON requests
app.use(express.urlencoded({ extended: true })); // Parses form data
app.use(express.static('public')); // Serves our HTML file
app.use(helmet()); // Secures HTTP headers

// --- 2. LOGGER SETUP (Week 3 Task) ---
const logger = winston.createLogger({
    level: 'info',
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'security.log' })
    ]
});

// Log that the app started
logger.info('Application started');

// In-memory array to act as our database
const usersDatabase = [];

// --- 3. REGISTRATION ROUTE ---
app.post('/register', async (req, res) => {
    const { email, password } = req.body;

    // Sanitize and Validate Input
    if (!validator.isEmail(email)) {
        logger.warn(`Registration failed: Invalid email format attempted (${email})`);
        return res.status(400).json({ error: 'Invalid email' });
    }

    // Check if user already exists
    if (usersDatabase.find(u => u.email === email)) {
        return res.status(400).json({ error: 'User already exists' });
    }

    try {
        // Password Hashing
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Save user to "database"
        usersDatabase.push({ email: email, password: hashedPassword });
        
        logger.info(`New user registered successfully: ${email}`);
        res.status(201).json({ message: 'Registration successful! You can now log in.' });
    } catch (error) {
        logger.error('Error during registration', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// --- 4. LOGIN ROUTE ---
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Find the user
    const user = usersDatabase.find(u => u.email === email);
    if (!user) {
        logger.warn(`Login failed: Unregistered email attempted (${email})`);
        return res.status(400).json({ error: 'Invalid email or password' });
    }

    try {
        // Compare the provided password with the hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        
        if (!isMatch) {
            logger.warn(`Login failed: Incorrect password for ${email}`);
            return res.status(400).json({ error: 'Invalid email or password' });
        }

        // Generate JWT Token
        const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: '1h' });
        
        logger.info(`User logged in successfully: ${email}`);
        res.json({ message: `Welcome securely, ${email}!`, token: token });
    } catch (error) {
        logger.error('Error during login', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.listen(PORT, () => {
    console.log(`Secure server running at http://localhost:${PORT}`);
});
