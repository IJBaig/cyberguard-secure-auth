# CyberGuard: Secure Identity Management & Authentication API

A robust, secure Node.js authentication application developed as part of a Cybersecurity Internship. This project demonstrates the practical implementation of modern web security defense mechanisms, transitioning from basic access control to an enterprise-grade security posture resilient against automated exploitation.

## 🛡️ Advanced Security Features Implemented
This application actively defends against the OWASP Top 10 vulnerabilities, having been penetration-tested against tools like SQLMap and Burp Suite:

* **Database Hardening (SQLi Prevention):** Replaced volatile memory with a persistent SQLite database utilizing **Prepared Statements** (parameterized queries) to completely neutralize SQL Injection attacks.
* **Cross-Site Request Forgery (CSRF) Protection:** Integrated `csurf` middleware to enforce cryptographic token validation on all state-changing requests, preventing unauthorized cross-origin execution.
* **API Security & CORS:** Implemented strict Cross-Origin Resource Sharing (CORS) rules and secured a sensitive data endpoint using explicit `x-api-key` header validation.
* **Intrusion Detection System (IDS):** Designed to work in tandem with **Fail2Ban** at the server level. Winston logs tag brute-force attempts, allowing Fail2Ban to update `iptables` and instantly drop malicious IPs.
* **Cryptographic Hashing & JWT:** Passwords are mathematically hashed using `bcrypt` (10-round salt). Stateless sessions are managed via secure JSON Web Tokens (JWT) with strict 1-hour expirations.
* **Advanced HTTP Headers:** Deployed `helmet.js` to enforce strict Content Security Policy (CSP) and HTTP Strict Transport Security (HSTS) max-age rules, mitigating XSS and protocol downgrade attacks.
* **Brute-Force Protection:** Integrated `express-rate-limit` to automatically block IP addresses after 5 failed authentication attempts within a 15-minute window.

## 💻 Tech Stack
* **Backend:** Node.js, Express.js
* **Database:** SQLite3
* **Security Middleware:** Helmet, Express-Rate-Limit, CORS, Csurf, Cookie-Parser
* **Authentication & Cryptography:** JSON Web Tokens (JWT), Bcrypt
* **Utilities:** Winston (Audit Logging), Validator (Input Sanitization)
* **Frontend:** Vanilla HTML/CSS/JS (Glassmorphism UI)
## 🚀 Getting Started

### Prerequisites
Ensure you have [Node.js](https://nodejs.org/) installed on your machine.

### Installation & Setup
1. Clone the repository:
   ```bash
   git clone [https://github.com/IJBaig/cyberguard-secure-auth.git](https://github.com/IJBaig/cyberguard-secure-auth.git)
   cd cyberguard-secure-auth
   ```
2. Install the required dependencies:
   ```bash
   npm install
   ```
3. Start the secure server (this will automatically generate the users.db file):
   ```bash
   npm start
   ```
4. Open your web browser and navigate to:
   ```bash
   http://localhost:3000
   ```
## 📝 Usage Instructions
1. **Register:** Create a new account. The system enforces strict password complexity (minimum 8 characters, requiring uppercase, lowercase, numbers, and special characters) and interacts securely with the SQLite database.

2. **Login:** Authenticate using your credentials. Upon success, the server validates your CSRF token and issues a secure JWT.

3. **Access Secure Vault:** Use the dashboard UI to test the API endpoint. The frontend will automatically attach the hardcoded x-api-key to authorize access to classified payload data.

4. **Forgot Password:** Test the two-factor identification by providing both your registered username and email to securely reset your password.

5. **Monitor Logs:** Check the generated security.log file in the root directory to see the real-time audit trail, which can be hooked into Fail2Ban or a centralized SIEM. 
   
## ⚖️ Copyright and License

Copyright © 2026 IJBaig

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 

*Note: This application was developed for educational and demonstration purposes as part of a cybersecurity internship.*
