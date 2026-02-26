# 🔐 LockBox — Zero-Knowledge Hybrid Encryption Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![PHP](https://img.shields.io/badge/PHP-7.0+-blue.svg)](https://www.php.net/)
[![Security Model](https://img.shields.io/badge/Architecture-Zero--Knowledge-brightgreen.svg)](https://en.wikipedia.org/wiki/Zero-knowledge_proof)
[![Crypto](https://img.shields.io/badge/Crypto-AES256%20%2B%20RSA2048%20%2B%20HMAC-orange.svg)](https://en.wikipedia.org/wiki/Hybrid_cryptosystem)

> Production-style educational implementation of a **Zero-Knowledge Hybrid Encryption System**

AES-256-CBC · RSA-2048-OAEP · HMAC-SHA256  
No key persistence · No database · No server-side key storage

---

# 🧠 1. Security Architecture

## Zero-Knowledge Design

LockBox is intentionally built so that:

- ❌ No public keys are stored
- ❌ No private keys are stored
- ❌ No encryption keys are written to disk
- ❌ No database exists
- ✅ Keys are processed in memory only
- ✅ If the server is compromised, no stored keys exist to steal

This significantly reduces post-breach cryptographic exposure.

---

# 🔐 2. Cryptographic Construction

LockBox implements a classic **Hybrid Cryptosystem**:

```
Plaintext
   ↓
AES-256-CBC (random 256-bit key + random IV)
   ↓
HMAC-SHA256 (Encrypt-then-MAC)
   ↓
RSA-2048-OAEP encrypts AES key
   ↓
Base64 Output
```

## Why Hybrid?

| Algorithm | Why Used |
|------------|----------|
| AES-256-CBC | Fast symmetric encryption for arbitrary-length data |
| RSA-2048-OAEP | Secure key encapsulation |
| HMAC-SHA256 | Tamper detection (integrity & authenticity) |

This avoids RSA encrypting large payloads directly.

---

# 🧪 3. Cryptographic Rationale

### AES-256-CBC
- Widely audited
- Secure when used with:
  - Random IV
  - Encrypt-then-MAC pattern

### RSA-2048-OAEP
- OAEP padding prevents classic RSA padding oracle attacks
- 2048-bit provides acceptable modern security margin

### HMAC-SHA256
- Prevents ciphertext tampering
- Verified before decryption
- Uses constant-time comparison

### Encrypt-then-MAC
LockBox follows the secure order:

```
Encrypt → MAC → Verify → Decrypt
```

This prevents padding oracle vulnerabilities.

---

# 🛡 4. Threat Model

## Assumed Attacker Capabilities

An attacker may:

- Intercept network traffic
- Modify encrypted payloads
- Attempt replay attacks
- Attempt malformed ciphertext attacks
- Attempt RSA abuse (DoS style)
- Gain read access to server filesystem
- Gain database dump (if one existed — none does)

## Attacker Cannot:

- Access private keys unless user leaks them
- Recover AES keys from ciphertext
- Bypass HMAC without MASTER_KEY
- Exploit padding oracle (due to MAC-first verification)

---

# 🔎 5. Attack Surface Analysis

| Surface | Risk | Mitigation |
|----------|------|------------|
| Network | MITM | HTTPS required |
| Ciphertext tampering | Corruption | HMAC verification |
| RSA padding oracle | Decryption oracle | OAEP + MAC-first validation |
| Log leakage | Key exposure | Sensitive fields filtered |
| Server breach | Key theft | Zero key storage |
| Replay | Limited | No session reuse of secrets |

---

# ⚠ 6. Security Limitations

This is critical and transparent.

## ❗ No Forward Secrecy

If a user’s private key is compromised in the future,  
previous ciphertexts encrypted with that key can be decrypted.

Mitigation would require:
- Ephemeral key exchange (e.g., ECDHE)
- Or session-based key agreement

---

## ❗ Server-Side Processing

Unlike full End-to-End encryption systems:

- Encryption occurs server-side
- Plaintext exists in server memory during request lifecycle

This is **not client-side E2EE**.

---

## ❗ No Built-in Rate Limiting

High-volume RSA abuse could increase CPU load.  
Recommended: add reverse proxy rate limiting.

---

## ❗ AES-CBC instead of AEAD

While secure in Encrypt-then-MAC mode,  
modern designs may prefer:

- AES-256-GCM
- XChaCha20-Poly1305

Future version may migrate.

---

# 🔁 7. Comparison with End-to-End Encryption

| Feature | LockBox | Full E2EE |
|----------|----------|------------|
| Server stores keys | ❌ No | ❌ No |
| Server sees plaintext | ✅ Yes (in memory) | ❌ No |
| Forward secrecy | ❌ No | ✅ Yes (usually) |
| Client-side crypto | ❌ | ✅ |
| Zero key persistence | ✅ | ✅ |

LockBox is **Zero-Knowledge storage**, not full client-side E2EE.

---

# 📂 8. Logging Policy

Logs include:

- Timestamp
- IP
- Operation type

Logs NEVER include:

- Private keys
- Public keys
- Master key
- AES keys
- Full plaintext
- HMAC values

Sensitive input fields are filtered before logging.

---

# ⚙ 9. Secure Deployment Guidelines

## Recommended

- Enforce HTTPS (TLS 1.2+)
- Set:
  - `session.cookie_httponly = 1`
  - `session.use_strict_mode = 1`
  - `session.cookie_secure = 1`
- Use strong MASTER_KEY (>= 32 bytes random)
- Store MASTER_KEY as environment variable
- Keep OpenSSL updated
- Restrict file permissions on logs directory

---

# 🧩 10. Project Structure

```
lockbox/
├── index.php
├── logs/
│   └── encryption.log
├── LICENSE
├── README.md
└── .gitignore
```

No key storage directory exists by design.

---

# 📜 11. Disclaimer

This software is provided:

- For educational and research purposes
- Without warranty
- Without guarantee of fitness for production

For handling highly sensitive data,  
consult a professional security engineer.

---

# 📊 12. Security Summary

| Property | Status |
|------------|---------|
| Confidentiality | Strong (AES-256) |
| Integrity | Strong (HMAC-SHA256) |
| Key Isolation | Strong (Zero storage) |
| Padding Oracle Resistance | Yes |
| Forward Secrecy | No |
| Client-side E2EE | No |

---

# 📄 License

MIT License

Copyright (c) 2026 0xjafari

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

---

<div align="center">

## 🔐 Zero-Knowledge by Design

If the server is compromised,  
there are no stored keys to steal.

Version 2.1.0  
Architecture: Zero-Knowledge Hybrid Cryptosystem  
License: MIT  

</div>
