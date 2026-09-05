# SecureChat — End-to-End Encrypted Messaging Model

A lightweight security model for messaging applications that protects user credentials with one-way hashing and secures device-to-device communication with end-to-end encryption (E2EE).

> **Note:** Replace the project name, tech stack, and code samples below with the specifics of your implementation. This README is a starting template covering the two core components you described: hashed login storage and encrypted message transport.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Login Security (Password Hashing)](#login-security-password-hashing)
- [Message Encryption (End-to-End)](#message-encryption-end-to-end)
- [Key Exchange & Session Setup](#key-exchange--session-setup)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [Project Structure](#project-structure)
- [Security Considerations](#security-considerations)
- [Roadmap](#roadmap)
- [License](#license)

---

## Overview

This project implements two independent but complementary security layers:

1. **Credential storage** — user passwords are never stored in plaintext. They are salted and hashed using a modern password-hashing algorithm before being written to the database.
2. **Message transport** — messages sent between users are encrypted on the sender's device with a one-time session key derived per message (via ECDH + HKDF) and can only be decrypted by the intended recipient. The server (or any intermediary) never has access to plaintext message content, private keys, the ECDH common secret, or any session key.

---

## Architecture

```
User A                       Server                       User B
------                       ------                       ------
ECDH key pair (long-term)                        ECDH key pair (long-term)
    │                                                        │
    ▼                                                        ▼
Public key ───────────► Stores/relays ───────────► Public key
                         public keys only
    │                                                        │
    ▼                                                        ▼
Derive common secret                        Derive common secret
(own private key +                          (own private key +
 User B's public key)                        User A's public key)
    │                                                        │
    ▼                                                        ▼
(same common secret on both sides — computed once, reused across messages)

Per message:
    │
    ▼
Generate random salt
    │
    ▼
HKDF(common secret, salt) → session key (AES-256)
    │
    ▼
Encrypt plaintext with
session key (AES-256-GCM)
    │
    ▼
salt + IV + ciphertext + tag ─► Stores/relays ─► salt + IV + ciphertext + tag
                                (never sees common
                                 secret or session key)
                                                        │
                                                        ▼
                                          HKDF(common secret, received salt)
                                                → same session key
                                                        │
                                                        ▼
                                              Decrypt with session key
                                                        │
                                                        ▼
                                                  Plaintext msg
```

The server acts purely as a relay/store for ciphertext, salts, and public keys — it never sees plaintext messages, private keys, the common secret, or any session key.

---

## Login Security (Password Hashing)

User credentials are protected using **Argon2i**, a memory-hard, adaptive password-hashing algorithm designed to resist GPU/ASIC brute-force and side-channel attacks. Hashing is one-way — the original password is never recoverable, even by the application itself.

Argon2i is the Argon2 variant optimized against side-channel attacks (as opposed to Argon2d, which is optimized against GPU cracking, or Argon2id, a hybrid of both). It's a solid choice specifically because login is an external-facing operation where timing/cache side-channel resistance matters most.

**Flow:**
1. User submits password on registration/login.
2. A unique random salt is generated per user (this is handled internally by the Argon2i library).
3. The password is passed through Argon2i along with configurable cost parameters: memory cost, time cost (iterations), and parallelism.
4. Only the resulting hash (which embeds the salt and parameters) is stored — never the plaintext password.
5. On login, the submitted password is verified against the stored hash using the same parameters.

**Example (Node.js / argon2):**
```js
const argon2 = require('argon2');

async function hashPassword(plainPassword) {
  return argon2.hash(plainPassword, {
    type: argon2.argon2i,
    memoryCost: 2 ** 16, // 64 MB
    timeCost: 3,
    parallelism: 1,
  });
}

async function verifyPassword(plainPassword, storedHash) {
  return argon2.verify(storedHash, plainPassword);
}
```

**Example (Python / argon2-cffi):**
```python
from argon2 import PasswordHasher
from argon2.low_level import Type

ph = PasswordHasher(type=Type.I, memory_cost=65536, time_cost=3, parallelism=1)

def hash_password(plain_password: str) -> str:
    return ph.hash(plain_password)

def verify_password(stored_hash: str, plain_password: str) -> bool:
    try:
        return ph.verify(stored_hash, plain_password)
    except Exception:
        return False
```

> Tune `memoryCost` / `timeCost` to your server's hardware — higher values slow down brute-force attempts but also slow down legitimate logins, so benchmark for a target verification time (commonly 250ms–1s).

---

## Message Encryption (End-to-End)

Messages are encrypted end-to-end using **AES-256-GCM**, a symmetric authenticated encryption algorithm that provides both confidentiality (nobody in transit can read the message) and integrity/authenticity (any tampering with the ciphertext is detected on decryption via the auth tag).

**Why AES-256-GCM:**
- 256-bit key length gives a very high security margin against brute force.
- GCM mode produces an authentication tag alongside the ciphertext, so the recipient can verify the message wasn't altered in transit — no separate MAC/HMAC step needed.
- It's fast enough for real-time messaging, including on mobile devices.

**High-level flow:**
1. The two users share one long-term **common secret**, derived once via ECDH (see [Key Exchange & Session Setup](#key-exchange--session-setup)) — but a **fresh session key is derived for every individual message** using a new random salt each time.
2. To send a message, the sender generates a fresh random salt, derives that message's one-time session key (common secret + salt, via HKDF), then generates a random 12-byte IV/nonce for AES-GCM.
3. The plaintext message is encrypted with AES-256-GCM using that message's session key and IV, producing ciphertext plus an authentication tag.
4. The **salt**, IV, ciphertext, and auth tag are all sent to the server, which relays them without being able to decrypt anything (the server never has the common secret or any session key).
5. The recipient re-derives that message's session key from the common secret and the received salt, decrypts using it and the received IV, and GCM automatically verifies the auth tag — if verification fails, the message is rejected as tampered/corrupted.
6. Once a message's session key has been used, it's discarded and never reused for another message.

> **Session key origin:** Each message's session key isn't pre-shared or sent over the network — only its ingredients (a random salt) are. The key itself is derived independently by each device from the **ECDH**-based common secret plus that salt. See [Key Exchange & Session Setup](#key-exchange--session-setup) for details.

**Example (Node.js crypto):**
```js
const crypto = require('crypto');

function encryptMessage(plaintext, sessionKey /* 32-byte Buffer, derived per message */) {
  const iv = crypto.randomBytes(12); // 96-bit nonce, required for GCM

  const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return { iv, ciphertext, authTag }; // pair this with the salt used to derive sessionKey
}

function decryptMessage({ iv, ciphertext, authTag }, sessionKey) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, iv);
  decipher.setAuthTag(authTag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return plaintext.toString('utf8');
}
```

**Example (Python / cryptography):**
```python
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_message(plaintext: bytes, session_key: bytes) -> tuple[bytes, bytes]:
    aesgcm = AESGCM(session_key)  # session_key must be 32 bytes for AES-256, derived per message
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # tag is appended to ciphertext
    return nonce, ciphertext  # pair this with the salt used to derive session_key

def decrypt_message(nonce: bytes, ciphertext: bytes, session_key: bytes) -> bytes:
    aesgcm = AESGCM(session_key)
    return aesgcm.decrypt(nonce, ciphertext, None)  # raises if tag verification fails
```

---

## Key Exchange & Session Setup

Each user has a long-term **ECDH public/private key pair**. Two users derive a shared secret once via ECDH, and then a **fresh session key is derived from that shared secret for every message**, using a random salt that's regenerated each time.

**How it works here:**
1. Each user generates their own ECDH key pair (public + private) on account setup. The private key never leaves the device; the public key is uploaded to the server.
2. To message another user, the sender fetches that user's public key from the server.
3. The sender combines *their own private key* with *the recipient's public key* through the ECDH protocol to compute a **common (shared) secret**. The recipient does the same in reverse (their private key + sender's public key) and arrives at the **exact same common secret** — without it ever being transmitted. This common secret stays the same between the same two users unless a key pair is rotated.
4. For **every message**, the sender generates a **fresh random salt**.
5. The common secret and that message's random salt are passed through **HKDF** to derive a one-time **session key**, which is the actual AES-256-GCM key used to encrypt that single message.
6. The random salt is sent alongside the ciphertext (it doesn't need to be secret — only the common secret and the resulting session key do). The recipient re-runs HKDF with the common secret and the received salt to derive the same session key, then decrypts.
7. Once a message's session key has been used, it's discarded and never reused.

Because the salt is different every time, the same common secret produces a completely different, unpredictable session key for every message — even though the underlying ECDH shared secret between the two users doesn't change.

**Example (Node.js crypto, using X25519 curve):**
```js
const crypto = require('crypto');

// Each user runs this once, on account setup, to generate their long-term key pair
function generateKeyPair() {
  return crypto.generateKeyPairSync('x25519');
}

// Run once per conversation/user-pair: derive the common (shared) secret
function deriveCommonSecret(myPrivateKey, theirPublicKey) {
  return crypto.diffieHellman({
    privateKey: myPrivateKey,
    publicKey: theirPublicKey,
  });
}

// Run for every message: derive a one-time session key from a fresh random salt
function deriveSessionKey(commonSecret) {
  const salt = crypto.randomBytes(16); // fresh per message, sent alongside the ciphertext
  const sessionKey = crypto.hkdfSync('sha256', commonSecret, salt, Buffer.from('e2ee-session-key'), 32);
  return { sessionKey, salt };
}
```

**Example (Python / cryptography, using X25519 curve):**
```python
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def generate_key_pair():
    private_key = X25519PrivateKey.generate()
    return private_key, private_key.public_key()

def derive_common_secret(my_private_key, their_public_key) -> bytes:
    return my_private_key.exchange(their_public_key)

def derive_session_key(common_secret: bytes) -> tuple[bytes, bytes]:
    salt = os.urandom(16)  # fresh per message, sent alongside the ciphertext
    session_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b'e2ee-session-key',
    ).derive(common_secret)
    return session_key, salt
```

**Additional recommendations:**
- Consider implementing a **key verification** step (e.g., safety numbers / QR code comparison) so users can confirm they're talking to the right person and not a man-in-the-middle intercepting the ECDH exchange.
- Deriving a fresh session key per message already gives strong per-message forward secrecy for the AES key itself — but note that the underlying **common secret** doesn't change unless a user's long-term ECDH key pair is rotated. If a user's private key is ever compromised, every past and future message between that pair can be recomputed. Consider periodic long-term key rotation if you want protection against that scenario too.
- The **salt** sent alongside each message's ciphertext doesn't need to be kept secret — only the common secret and the derived session key do — but make sure it's never skipped or reused, since salt reuse with the same common secret would produce the same session key twice.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Password hashing | Argon2i |
| Message encryption | AES-256-GCM |
| Key exchange | ECDH (e.g., X25519 curve) |
| Transport | TLS (HTTPS/WSS) in addition to E2EE |
| Backend | _e.g., Node.js / Express_ |
| Database | _e.g., PostgreSQL / MongoDB_ |

---

## Getting Started

```bash
# Clone the repository
git clone https://github.com/your-username/your-repo.git
cd your-repo

# Install dependencies
npm install

# Set up environment variables
cp .env.example .env

# Run the app
npm start
```

### Environment Variables

```
DATABASE_URL=
ARGON2_MEMORY_COST=65536
ARGON2_TIME_COST=3
JWT_SECRET=
```

---

## Project Structure

```
├── src/
│   ├── auth/           # Registration, login, password hashing
│   ├── crypto/         # Key generation, encryption/decryption utilities
│   ├── messages/       # Message send/receive logic
│   ├── models/         # Database models
│   └── routes/         # API endpoints
├── tests/
├── .env.example
└── README.md
```

---

## Security Considerations

- **Never log plaintext passwords or messages.**
- **Never store or transmit private keys, the ECDH common secret, or any session key.**
- **Never reuse a per-message salt or IV/nonce** — reusing a salt with the same common secret regenerates the same session key, and reusing an IV under the same AES-GCM key breaks its security guarantees.
- Use HTTPS/TLS for all network traffic, even though messages are already encrypted end-to-end — this protects metadata and prevents tampering.
- Rotate and version your Argon2i cost parameters (memory/time cost) as hardware improves.
- Consider periodic rotation of users' long-term ECDH key pairs — since the common secret itself doesn't change between rotations, a compromised private key would expose every past and future session key derived from it.
- Consider rate-limiting login attempts to mitigate brute-force attacks.
- Have this design reviewed by a security professional before using it in production — cryptography is easy to get subtly wrong.

---

## Roadmap

- [ ] Add long-term ECDH key pair rotation (to limit exposure if a private key is ever compromised)
- [ ] Add multi-device support per user
- [ ] Add message expiration / disappearing messages
- [ ] Add out-of-band key verification (safety numbers)

---

