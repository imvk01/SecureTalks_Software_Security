# Vikash_SSHW — Secure Messaging System

**Course:** Software Security Homework
**Professor:** Prof. Dr. Rand Kouatly
**Institution:** EU University of Applied Science
**Semester:** Summer 2026

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Requirements](#2-requirements)
3. [Installation & Setup](#3-installation--setup)
4. [Running the Application](#4-running-the-application)
5. [Demo Accounts](#5-demo-accounts)
6. [How to Use the Application](#6-how-to-use-the-application)
7. [Testing the Security Features](#7-testing-the-security-features)
8. [Attack Simulations](#8-attack-simulations)
9. [Security Design Summary](#9-security-design-summary)
10. [Project Structure](#10-project-structure)
11. [Feature Implementation Checklist](#11-feature-implementation-checklist)

---

## 1. Project Overview

Vikash_SSHW is a web-based secure messaging application that demonstrates core cryptographic principles including symmetric encryption, message integrity verification, secure password storage, and common attack detection. It is built with Python (Flask) and uses industry-standard libraries.

**Key security features:**
- AES-256-GCM symmetric encryption for all messages
- HMAC-SHA256 message integrity verification
- bcrypt password hashing (cost factor 12)
- Replay attack prevention via per-message nonces
- Account lockout after repeated failed login attempts
- Full security event logging

---

## 2. Requirements

- **Python 3.8 or above**
- **pip** (Python package manager)
- A modern web browser (Chrome, Firefox, Edge)

> No other software or database is required. All data is stored in memory during the session.

---

## 3. Installation & Setup

### Step 1 — Download and extract the project

Unzip the submitted file. You should see a `Vikash_SSHW.zip/` folder containing `app.py`, `requirements.txt`, and the rest of the project.

### Step 2 — Open a terminal in the project folder

```bash
cd Vikash_SSHW
```

### Step 3 — Create a virtual environment (recommended)

```bash
python -m venv venv
```

Activate the virtual environment:

**Windows:**
```bash
venv\Scripts\activate
```

**macOS / Linux:**
```bash
source venv/bin/activate
```

### Step 4 — Install dependencies

```bash
pip install -r requirements.txt
```

This installs: `Flask`, `Flask-SocketIO`, `cryptography`, and `bcrypt`.

---

## 4. Running the Application

```bash
python app.py
```

You will see the following output in the terminal:

```
=======================================================
  Vikash_SSHW — Secure Messaging System
  Software Security HW — University of Europe for Applied Sciences
=======================================================
  Open: http://127.0.0.1:5000
  Demo accounts:
    alice / alice123
    bob   / bob456
    carol / carol789
    dave  / dave000
=======================================================
```

Open your browser and go to: **http://127.0.0.1:5000**

> To stop the server, press `Ctrl + C` in the terminal.

---

## 5. Demo Accounts

Four accounts are pre-loaded automatically when the server starts:

| Username | Password  | Display Name |
|----------|-----------|--------------|
| alice    | alice123  | Alice        |
| bob      | bob456    | Bob          |
| carol    | carol789  | Carol        |
| dave     | dave000   | Dave         |

You can also register new accounts from the login screen.

---

## 6. How to Use the Application

### Registering a New Account
1. On the login screen, click **Register**
2. Enter a username (minimum 3 characters), display name, and password (minimum 6 characters)
3. Click **Register** — your password is immediately hashed with bcrypt

### Logging In
1. Enter your username and password
2. Click **Login**
3. After 5 consecutive wrong password attempts, the account is locked

### Sending Messages
1. After login, select a contact from the left sidebar
2. Type your message in the input box and press **Send** or hit Enter
3. Each message is encrypted with AES-256-GCM before being stored or transmitted
4. Below each message bubble, a ciphertext preview shows the encrypted form

### Tabs in the Interface

| Tab | What it shows |
|-----|---------------|
| **Chat** | The messaging interface |
| **Crypto** | Live encryption details — algorithm, key fingerprint, IV length, HMAC |
| **Attacks** | Buttons to trigger MITM, Replay, and Brute Force simulations |
| **Logs** | Real-time security event log |

---

## 7. Testing the Security Features

### Authentication & Account Lockout
1. Log in as `alice` with the correct password → see `LOGIN_OK` in the Logs tab
2. Log out, then try logging in with a wrong password several times
3. After 5 failures, the account locks → see `ACCOUNT_LOCKED` in the Logs tab

### Encrypted Messaging
1. Log in as `alice`, select `bob` as contact
2. Send any message
3. Below the message bubble, you will see the ciphertext preview, IV, and HMAC values
4. Open the **Crypto** tab to see the full cryptographic parameters for the conversation

### Verifying Message Integrity
- Every message is verified with HMAC-SHA256 when displayed
- If a message passes verification, it shows `integrity: ok`
- If it fails (e.g., during MITM simulation), it shows `⚠️ Tampered or replayed message`

### Viewing the Security Log
- Click the **Logs** tab to see all events in the browser
- The same events are also written to `logs/security.log` on disk
- Events include: `LOGIN_OK`, `LOGIN_FAIL`, `MSG_ENCRYPTED`, `MSG_DECRYPTED`, `MITM_ATTEMPT`, `REPLAY_DETECTED`, `BF_ATTEMPT`, etc.

---

## 8. Attack Simulations

All simulations are accessible from the **Attacks** tab. You must select a contact and send at least one message before running them.

### Man-in-the-Middle (MITM)
**What it does:** Intercepts the last sent message, flips 3 bytes in the ciphertext (positions 0, 5, 10), then attempts to decrypt the tampered message.

**Expected result:** The HMAC-SHA256 verification fails immediately. The AES-GCM authentication tag also independently detects the corruption. The message is rejected with `detected: true`.

**Defense demonstrated:** HMAC-SHA256 over the ciphertext + AES-GCM auth tag.

---

### Replay Attack
**What it does:** Captures the nonce from the last sent message and attempts to re-submit it as a new message.

**Expected result:** The server looks up the nonce in its seen-nonce store. Since every nonce is registered at send time, the duplicate is detected immediately with `detected: true`.

**Defense demonstrated:** Per-message 128-bit nonce tracked in a server-side set.

---

### Brute Force
**What it does:** Tries 10 common passwords (`password`, `123456`, `letmein`, etc.) against the `alice` account's bcrypt hash, measuring the time each attempt takes.

**Expected result:** Each attempt takes approximately 100–300ms due to bcrypt's cost factor 12. The output shows the attempt count, timing per guess, and a slowdown comparison versus raw SHA-256 (bcrypt is typically ~10 billion times slower).

**Defense demonstrated:** bcrypt cost factor 12 + account lockout after 5 real login failures.

---

## 9. Security Design Summary

### Encryption
| Property | Value |
|----------|-------|
| Algorithm | AES-256-GCM |
| IV | 96-bit, randomly generated per message |
| Auth Tag | 128-bit (built into GCM) |
| Integrity | HMAC-SHA256 (additional layer over ciphertext) |

### Key Management
| Property | Value |
|----------|-------|
| Key derivation | PBKDF2-SHA256, 100,000 iterations |
| Key source | Sorted user pair + server secret |
| Hardcoded keys | Never — derived at runtime |
| Key fingerprint | SHA-256 of derived key (first 32 hex chars) |

### Authentication
| Property | Value |
|----------|-------|
| Password hashing | bcrypt, cost factor 12 |
| Session token | 256-bit CSPRNG (`secrets.token_hex(32)`) |
| Account lockout | After 5 failed login attempts |
| Replay protection | 128-bit nonce per message, stored in server set |

### Logging
All of the following are logged to both the in-browser UI and `logs/security.log`:
- Successful and failed login attempts (with IP address)
- Registration events
- Every encryption and decryption operation
- Failed decryption attempts (integrity violations)
- All attack simulation triggers and outcomes
- Account lockout events

---

## 10. Project Structure

```
Vikash_SSHW/
├── app.py                  # Main Flask backend — all crypto, auth, routes, attacks
├── requirements.txt        # Python dependencies
├── README.md               # This file (user guide)
├── templates/
│   └── index.html          # Single-page web interface
├── static/
│   ├── css/
│   │   └── style.css       # Application stylesheet
│   └── js/
│       └── app.js          # Frontend JavaScript (chat, crypto display, attacks)
└── logs/
    └── security.log        # Security event log (written at runtime)
```

---

## 11. Feature Implementation Checklist

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| User registration | ✅ Done | `/api/register` — bcrypt hash stored |
| User login | ✅ Done | `/api/login` — bcrypt verify + session token |
| Secure password storage | ✅ Done | bcrypt, cost factor 12 |
| Session handling | ✅ Done | 256-bit CSPRNG token in Flask session |
| AES symmetric encryption | ✅ Done | AES-256-GCM via `cryptography` library |
| Non-hardcoded keys | ✅ Done | PBKDF2-SHA256 derived at runtime |
| Message integrity | ✅ Done | HMAC-SHA256 + GCM auth tag |
| Tamper detection | ✅ Done | HMAC mismatch raises ValueError |
| MITM attack simulation | ✅ Done | `/api/attack/mitm` |
| Replay attack simulation | ✅ Done | `/api/attack/replay` |
| Brute force simulation | ✅ Done | `/api/attack/bruteforce` |
| Login event logging | ✅ Done | File + in-memory log |
| Encryption event logging | ✅ Done | Every encrypt/decrypt logged |
| Failed decryption logging | ✅ Done | `DECRYPT_FAIL` event |
| Web-based UI | ✅ Done | Flask + SocketIO + HTML/CSS/JS |
| Real-time messaging | ✅ Done | Flask-SocketIO rooms |