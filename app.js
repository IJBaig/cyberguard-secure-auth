const winston = require('winston');

// 1. Configure the Logger
const logger = winston.createLogger({
    level: 'info', // Logs 'info' and anything more severe ('warn', 'error')
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json() // JSON format is standard for security tools (like Splunk) to read
    ),
    transports: [
        // Print logs to the terminal
        new winston.transports.Console({
            format: winston.format.simple() 
        }),
        // Save logs to a persistent file
        new winston.transports.File({ filename: 'security.log' })
    ]
});

// 2. Simulate Application Events
logger.info('Application started successfully on port 8080.');

// Simulate a security warning (e.g., someone typing a bad password)
logger.warn('Failed login attempt detected from IP: 192.168.1.50');

// Simulate a critical security error (e.g., a database crash or SQLi attempt)
logger.error('CRITICAL: Database connection lost during authentication phase!');
