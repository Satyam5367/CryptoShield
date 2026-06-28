# CryptoShield — Secure File Encryption System

End-to-end encrypted file sharing using AES-256-GCM, RSA-2048, and digital signatures.
Built with Python, Flask, and the `cryptography` library. Deployed via Docker on Linux.

---

## Screenshots

```
┌─────────────────────────────────────────────────────┐
│  CryptoShield — Secure File Sharing                 │
│  Send File │ Inbox │ My Keys                        │
├─────────────────────────────────────────────────────┤
│  📤 Encrypt & Send         🔐 How It Works          │
│  Recipient: [alice] [bob]  1. AES-256-GCM key gen  │
│  Private Key: [_______]    2. File encrypted        │
│  File: [Choose File]       3. Ciphertext signed     │
│  [🔒 Encrypt & Send]       4. AES key RSA-wrapped   │
│                            5. Bundle uploaded        │
│  🔑 Decrypt File                                    │
│  File ID:  [1    ]         📥 Inbox                 │
│  Priv Key: [_____]         secret.txt  Bob → Alice  │
│  Sender:   [_____]         [Decrypt] [Verify]       │
│  [🔓 Decrypt & Verify]                              │
└─────────────────────────────────────────────────────┘
```

---

## Features

- **AES-256-GCM** authenticated symmetric encryption
- **RSA-2048 OAEP** secure key exchange
- **RSA-PSS digital signatures** for integrity and non-repudiation
- **Verify-only endpoint** — check signature without decrypting
- **JWT-based authentication** with BCrypt password hashing
- **Immutable audit logging** for every encrypt, decrypt, verify action
- **Web dashboard** for end-to-end encrypted file sharing
- **Dockerized** on Linux with secrets via environment variables

---

## How It Works

```
Alice → Bob encrypted file transfer:

1. Ephemeral AES-256 key generated (os.urandom(32))
2. File encrypted: AES-256-GCM(file, aes_key) → ciphertext + auth_tag
3. Ciphertext signed: RSA-PSS(ciphertext, alice_private_key) → signature
4. AES key wrapped: RSA-OAEP(aes_key, bob_public_key) → wrapped_key
5. Bundle = {ciphertext, nonce, wrapped_key, signature} → server

Bob decrypts:
1. RSA-OAEP decrypt: wrapped_key → aes_key  (only Bob can do this)
2. Verify signature: RSA-PSS verify(ciphertext, signature, alice_public_key)
3. AES-GCM decrypt: aes_key + nonce → plaintext
```

---

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/Satyam5367/CryptoShield.git
cd CryptoShield
cp .env.example .env
```

### 2. Run with Docker

```bash
docker-compose up --build
# API at http://localhost:5001
```

### 3. Run locally

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python run.py
```

---

## Demo

```bash
# Full API demo (requires docker-compose up)
python demo.py

# Offline crypto-only demo (no API needed)
python demo.py --offline
```

**Offline demo output:**
```
[Step 1] Generating RSA-2048 key pairs for Alice and Bob...
  ✓ Alice: RSA-2048 key pair generated
  ✓ Bob:   RSA-2048 key pair generated

[Step 2] AES-256-GCM encryption test...
  ✓ Plaintext:  Confidential: Q4 financial projections
    Nonce:      3f8a2b1c9e7d4f0a...
    Ciphertext: 8f3a2b4c1e9d7f0b...
  ✓ AES-256-GCM roundtrip: PASSED

[Step 4] Tamper detection test...
  ✓ Tampered data signature valid: False ← correctly rejected

[Step 5] Full encrypt-and-sign → decrypt-and-verify (Alice → Bob)...
  ✓ Bob received: 'TOP SECRET: Access credentials...'
  ✓ Signature verified: PASSED

[Step 6] Wrong recipient key test...
  ✓ Eve's decryption: BLOCKED

[Step 7] Tampered bundle test...
  ✓ Tampered bundle: REJECTED
```

---

## Generate Key Pairs

```bash
python keygen.py --name alice
# keys/alice_private.pem  ← keep LOCAL, never upload
# keys/alice_public.pem   ← upload to /keys/upload

python keygen.py --name bob
```

---

## API Reference

| Method | Endpoint                | Description                  | Auth |
|--------|-------------------------|------------------------------|------|
| POST   | /auth/register          | Register user                | No   |
| POST   | /auth/login             | Login, get JWT               | No   |
| GET    | /auth/me                | Current user info            | Yes  |
| POST   | /keys/upload            | Upload RSA public key        | Yes  |
| GET    | /keys/user/{id}         | Get a user's public key      | Yes  |
| GET    | /keys/users             | List users with keys         | Yes  |
| POST   | /files/encrypt-upload   | Encrypt + sign + upload      | Yes  |
| GET    | /files/inbox            | Files received               | Yes  |
| GET    | /files/sent             | Files sent                   | Yes  |
| POST   | /files/decrypt/{id}     | Decrypt + verify signature   | Yes  |
| POST   | /files/verify/{id}      | Verify signature only        | Yes  |

---

## SAST — Bandit

```bash
bandit -r app/ -c bandit.yaml -f txt -o bandit_report.txt
```

Pre-generated: `bandit_report.txt` — **Result: PASSED** (0 medium/high issues)
Crypto engine: **CLEAN** — no weak algorithms, no hardcoded keys, ephemeral AES keys only.

---

## Tests

```bash
pytest tests/ -v
```

Covers: AES roundtrip, wrong key rejection, RSA-PSS sign/verify, tamper detection,
full API encrypt→decrypt flow, non-recipient 403 block.

---

## Security Design

| Property          | Implementation                                    |
|-------------------|---------------------------------------------------|
| Confidentiality   | AES-256-GCM symmetric encryption                  |
| Key exchange      | RSA-2048 OAEP (only recipient unwraps AES key)    |
| Integrity         | AES-GCM auth tag + RSA-PSS digital signature      |
| Non-repudiation   | RSA-PSS signature by sender's private key         |
| Authentication    | JWT HS256, 1-hour expiry                          |
| Password storage  | BCrypt adaptive hashing                           |
| Secrets           | Environment variables, never hardcoded            |
| Audit trail       | Immutable AuditLog — all actions recorded         |
| Container         | Non-root Docker user                              |
| SAST              | Bandit (see bandit_report.txt)                    |

---

## Tech Stack

Python · Flask · cryptography library · SQLite/PostgreSQL · Docker · Linux
