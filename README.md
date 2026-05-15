## SecureVault — Secure Password Management System

A locally-hosted password manager developed as part of my Final Year Project 2 at UniKL MIIT. Built using Python and Flask, SecureVault allows users to securely store, manage, and generate passwords with AES-256 encryption and multi-factor authentication.

## Features
- AES-256 encrypted password vault
- Master password hashing with Argon2id
- Two-factor authentication — TOTP (Google Authenticator) + Email OTP
- Biometric account recovery simulation
- Password expiry tracking (90-day guideline)
- Activity log
- Configurable session timeout
- Account lockout after failed attempts

## Tech Stack
- Backend: Python 3.9, Flask
- Database: SQLite
- Encryption: Fernet (AES-256)
- Hashing: Argon2-cffi
- 2FA: PyOTP, Flask-Mail
- Security Testing: OWASP ZAP 2.17.0
- Frontend: HTML, CSS, JavaScript

## Security Testing
OWASP ZAP automated scan results:
- Before fixes: 11 alerts
- After fixes: 9 alerts
- Fixed: Anti-clickjacking header, X-Content-Type-Options, Session cookie flags

## Developer
**Nur Irdina Syaqela Binti Mohd Shukri**
Bachelor of IT (Hons) in Computer System Security (BCSS)
UniKL Malaysian Institute of Information Technology
dinashukri9@gmail.com
