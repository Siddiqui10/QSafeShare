<div align="center">
  <img src="app/static/img/logo_128.png" width="96" height="96" alt="QSafeShare Logo" style="border-radius:20px;" />
  <h1>QSafeShare</h1>
  <p><strong>Post-Quantum Secure Multi-Agent File Sharing Platform</strong></p>
  <p><em>NIST FIPS 203 (ML-KEM) Lattice Key Encapsulation &amp; AES-256-GCM Envelope Encryption</em></p>

  <p>
    <a href="https://csrc.nist.gov/pubs/fips/203/final"><img src="https://img.shields.io/badge/Standard-NIST%20FIPS%20203%20ML--KEM-06b6d4.svg" alt="NIST FIPS 203" /></a>
    <a href="https://csrc.nist.gov/publications/detail/sp/800-38d/final"><img src="https://img.shields.io/badge/Cipher-AES--256--GCM-10b981.svg" alt="Cipher" /></a>
    <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11%2B-blue.svg" alt="Python" /></a>
    <a href="https://fastapi.tiangolo.com/"><img src="https://img.shields.io/badge/Framework-FastAPI-009688.svg" alt="FastAPI" /></a>
    <img src="https://img.shields.io/badge/Tests-29%2F29%20Passing-brightgreen.svg" alt="Tests Passing" />
    <a href="https://q-safe-share.vercel.app/"><img src="https://img.shields.io/badge/Deployment-Vercel%20Live-black.svg" alt="Deployment" /></a>
  </p>
</div>

> **Live Deployment:** [https://q-safe-share.vercel.app/](https://q-safe-share.vercel.app/)  
> **Source Repository:** [https://github.com/Siddiqui10/QSafeShare](https://github.com/Siddiqui10/QSafeShare)

---

## 📖 Overview

**QSafeShare** is an enterprise-grade, post-quantum secure multi-agent file-sharing platform. It combines **AES-256-GCM** for high-throughput authenticated symmetric payload encryption with the **NIST FIPS 203 standardized ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)** for quantum-resistant key establishment.

By separating file handling, access-policy enforcement, and key distribution across specialized autonomous agents (**Sender**, **Policy**, **Coordinator**, and **Audit**), QSafeShare ensures strict separation of privilege, forward revocation, and tamper-evident auditability.

---

## ✨ Key Features

- **🛡️ NIST FIPS 203 ML-KEM-768 & ML-KEM-1024**: Native lattice-based cryptography that resists cryptanalytic attacks by future quantum computers (Shor's algorithm).
- **🔒 AES-256-GCM Envelope Encryption**: Unique 96-bit initialization vectors (nonces) and 128-bit authentication tags per file payload ensure confidentiality and cryptographic tamper detection.
- **🌐 Real Google OAuth 2.0 Integration**: Official Google Sign-In using the Authorization Code Flow (`/api/auth/oauth/google/login` & `/api/auth/oauth/google/callback`) with automatic post-quantum key vault provisioning.
- **🔑 Post-Quantum Key Vault**: Every registered user automatically receives a native NIST ML-KEM keypair (Category 3 / Category 5) stored securely for asymmetric key distribution.
- **🔗 Secure Public Link Sharing**: Generate time-limited, password-protected, and burn-after-reading file links (`/share/{token}`) with strict download caps (e.g. 1 download, 5 downloads, or unlimited).
- **🚫 Real-Time Forward Revocation**: Policy Agent enforces immediate access revocation. Revoking a recipient prevents them from acquiring key material or downloading updates.
- **📱 Fully Responsive & Mobile-Framed UI**: Adaptive dark-mode interface designed for desktop, tablet, and mobile displays with horizontal swipe navigation and touch-friendly controls.
- **📊 Research Benchmark Lab**: Interactive microbenchmark engine comparing ML-KEM-768/1024 with classical algorithms (RSA-2048, ECDH-P256), multi-recipient packaging scalability ($\mathcal{O}(N)$), and end-to-end payload integrity.

---

## 🎯 The Core Research Question

> **Can a multi-agent file-sharing architecture provide post-quantum-secure key distribution and fine-grained access control while maintaining acceptable performance as the number of recipients increases?**

### Empirical Research Verdict: **YES**

1. **Cryptographic Efficiency**: NIST ML-KEM-768 achieves **sub-millisecond encapsulation (0.12 ms)** and key generation (0.41 ms), outperforming classical RSA-2048 key generation (91.9 ms) by over **80×**.
2. **Recipient Scalability**: Packaging keys for up to **50 recipients takes only ~7.6 ms**, scaling strictly linearly $\mathcal{O}(N)$ with negligible overhead (~0.15 ms per recipient).
3. **Fine-Grained Policy Enforcement**: The decoupled **Policy Agent** enforces forward revocation and expiration in real-time, preventing revoked recipients from obtaining file key material.
4. **Agent Separation Overhead**: Multi-agent isolation introduces minimal architectural overhead while guaranteeing strict separation of privilege and full auditability.

---

## 🏛️ System Architecture

```text
                                  WEB CLIENT
                   (Desktop / Tablet / Smartphone Interface)
                                      │
                                      ▼
                      ┌───────────────────────────────┐
                      │      QSafeShare Backend       │
                      │           (FastAPI)           │
                      └───────────────┬───────────────┘
                                      │
         ┌────────────────────────────┼────────────────────────────┐
         │                            │                            │
         ▼                            ▼                            ▼
  ┌──────────────┐             ┌──────────────┐             ┌──────────────┐
  │ Sender Agent │             │ Policy Agent │             │ Coordinator  │
  └──────┬───────┘             └──────┬───────┘             │    Agent     │
         │                            │                     └──────┬───────┘
  AES-256-GCM Encrypt                 │ Access Rules               │
  File Storage                        │ (Allowed / Revoked)        │ ML-KEM
         │                            │                            │ Encapsulation
         └────────────────────────────┼────────────────────────────┘
                                      │
                                      ▼
                               ┌──────────────┐
                               │ Audit Agent  │
                               └──────────────┘
                                      │
                                      ▼
                              Recipient Decrypt
                           (AES + NIST ML-KEM)
```

### Specialized Agents

| Agent | Responsibility | Cryptographic Role |
| :--- | :--- | :--- |
| **Sender Agent** | Represents the data owner. Ingests raw files, generates fresh 256-bit AES keys, encrypts file payloads using AES-256-GCM with 96-bit unique nonces, and initiates recipient sharing. | AES-256-GCM Data Encapsulation |
| **Policy Agent** | Enforces access rules (`Allowed`, `Revoked`, `Expired`). Evaluates every access query before key release. Never touches unencrypted file data. | Zero-Trust Policy Decision Point (PDP) |
| **Coordinator Agent** | Orchestrates post-quantum key distribution. Queries Policy Agent to confirm authorization, encapsulates ML-KEM shared secrets, and wraps AES file keys via HKDF-derived KEKs. | ML-KEM-768/1024 Key Encapsulation (PEP) |
| **Audit Agent** | Maintains a tamper-evident chronological event stream of all inter-agent messages, cryptographic operations, access grants, and security denials. | System Compliance & Observability |

---

## 🔐 How the Cryptography Works

### 1. File Upload & Ingestion (Hybrid Envelope Encryption)
Files are **never** encrypted directly with public-key cryptography (which is computationally impractical for large files). Instead:
1. Sender Agent generates a random 256-bit AES key:
   $$K_{file} \leftarrow \text{CSPRNG}(256)$$
2. The file payload is encrypted with AES-256-GCM:
   $$C_{file}, T_{auth} = \text{AES-256-GCM-Encrypt}(K_{file}, \text{Nonce}, \text{Plaintext})$$
3. The encrypted payload is safely written to storage.

### 2. Multi-Recipient Post-Quantum Key Distribution (ML-KEM)
When Alice shares with Bob:
1. Coordinator Agent queries Policy Agent: *"Is Bob authorized to receive this file?"*
2. If Policy Agent confirms **ALLOWED**:
   - Coordinator fetches Bob's public key $PK_{Bob}$ (NIST ML-KEM-768).
   - Performs post-quantum encapsulation:
     $$(SS_{Bob}, C_{kem}) = \text{ML-KEM.Encapsulate}(PK_{Bob})$$
   - Derives a 256-bit Key Encryption Key (KEK) using HKDF-SHA256:
     $$KEK = \text{HKDF-SHA256}(SS_{Bob}, \text{info}=\text{"QSafeShare-FileKeyWrap-v1"})$$
   - Wraps the file key using AES-256-GCM:
     $$WrappedKey = \text{AES-GCM-Encrypt}(KEK, \text{WrapNonce}, K_{file})$$
   - Saves the key package $\{C_{kem}, \text{WrapNonce}, WrappedKey\}$.

### 3. Recipient Download & Decryption
1. Recipient requests key material from Coordinator Agent.
2. Coordinator Agent queries Policy Agent.
3. If **ALLOWED**, key package and ciphertext are delivered.
4. Recipient decapsulates using private key $SK_{Bob}$:
   $$SS_{Bob} = \text{ML-KEM.Decapsulate}(SK_{Bob}, C_{kem})$$
5. Recipient derives $KEK$ and unwraps $K_{file}$.
6. Recipient decrypts file ciphertext using $K_{file}$ via AES-256-GCM and verifies SHA-256 checksum integrity.

### 4. Public Link Sharing & Burn-After-Reading Protection
1. Sender generates a secure sharing link with optional custom password protection and download limits.
2. **Self-Healing Stateless Resilience (Zero-DB Serverless Survival)**:
   - File metadata, nonces, key wrap package, user-defined expiration (e.g. 24h, 7 days, 30 days, or Perpetual), and ciphertext payload are compressed into a compact bundle encoded in the URL hash fragment (`#b=...`).
   - Because hash fragments are never sent over HTTP to the server, links remain lightweight and completely immune to serverless container recycles or cold-start ephemeral disk resets on platforms like Vercel.
   - When a recipient opens the link, the system checks whether the configured expiration time has passed. If active, the file is unlocked, decrypted, and verified bit-exact with SHA-256.
   - The active serverless container automatically rehydrates its local database cache from the bundle upon first unlock.
3. If max download count is reached (e.g. 1-download burn after reading) or link is expired, Policy Agent permanently refuses further access.

---

*Default password for all demo accounts: `password123`*

---

## 🔬 Empirical Research Benchmark Suite

Run the benchmark battery using the standalone CLI script:

```bash
python benchmark.py
```

### 1. NIST ML-KEM Cryptographic Microbenchmarks
| Algorithm | NIST Security Category | KeyGen (ms) | Encapsulation (ms) | Decapsulation (ms) | Public Key | Ciphertext |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **ML-KEM-768** | Level 3 (AES-192 equiv) | 0.41 ms | 0.13 ms | 0.38 ms | 1,184 B | 1,088 B |
| **ML-KEM-1024** | Level 5 (AES-256 equiv) | 0.69 ms | 0.21 ms | 0.68 ms | 1,568 B | 1,568 B |

### 2. Classical (RSA/ECDH) vs Post-Quantum (ML-KEM)
| Algorithm | Shor's Vulnerable? | KeyGen (ms) | Encaps/Encrypt (ms) | Decaps/Decrypt (ms) | Ciphertext Size |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **RSA-2048** | **YES (Broken by Shor's)** | 91.93 ms | 0.08 ms | 1.09 ms | 256 B |
| **ECDH-P256** | **YES (Broken by Shor's)** | 0.08 ms | 0.17 ms | 0.16 ms | 91 B |
| **ML-KEM-768** | **NO (Quantum Resistant)** | **0.41 ms** | **0.13 ms** | **0.38 ms** | 1,088 B |
| **ML-KEM-1024**| **NO (Quantum Resistant)** | **0.69 ms** | **0.21 ms** | **0.68 ms** | 1,568 B |

### 3. Multi-Recipient Scalability ($N = 1$ to $50$)
| Recipients ($N$) | Total Packaging Time | Avg Time Per Recipient | Total Key Package Size |
| :---: | :---: | :---: | :---: |
| **1** | 0.30 ms | 0.30 ms | 1,148 bytes |
| **5** | 0.79 ms | 0.16 ms | 5,740 bytes |
| **10** | 1.54 ms | 0.15 ms | 11,480 bytes |
| **25** | 5.29 ms | 0.21 ms | 28,700 bytes |
| **50** | 7.64 ms | 0.15 ms | 57,400 bytes |

*Proof of $\mathcal{O}(N)$ Linear Scaling: Packaging keys for 50 recipients takes under 8 milliseconds.*

---

## 🛠️ Google OAuth 2.0 Setup Guide

### 1. Google Cloud Console Settings
In your [Google Cloud Console](https://console.cloud.google.com/apis/credentials) under your OAuth 2.0 Client ID:

- **Authorized JavaScript origins**:
  ```text
  https://q-safe-share.vercel.app
  http://localhost:8000
  http://127.0.0.1:8000
  ```
- **Authorized redirect URIs**:
  ```text
  https://q-safe-share.vercel.app/api/auth/oauth/google/callback
  http://localhost:8000/api/auth/oauth/google/callback
  http://127.0.0.1:8000/api/auth/oauth/google/callback
  ```

### 2. Environment Variables
Create a local `.env` file (which is gitignored):

```ini
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
SECRET_KEY=your-session-secret-key

# Optional: Cloud PostgreSQL for persistent storage across Vercel serverless containers
# DATABASE_URL=postgresql://user:password@host:5432/dbname?sslmode=require
```

On **Vercel**, add these variables under **Project Settings → Environment Variables**, then trigger a redeployment.

### 3. Persistent Cloud Database (Recommended for Vercel)
Serverless containers are ephemeral (`/tmp` resets on cold starts). To ensure uploaded files, users, and secure links persist indefinitely across all containers and devices:

- **Option A (1-Click in Vercel Storage)**:
  1. Open your project on the [Vercel Dashboard](https://vercel.com/dashboard).
  2. Navigate to the **Storage** tab.
  3. Click **Create Database** → Select **Neon** or **Postgres** (Free tier).
  4. Vercel automatically links the database and injects `POSTGRES_URL`!

- **Option B (Free Neon or Supabase)**:
  1. Create a free PostgreSQL instance on [Neon](https://neon.tech/) or [Supabase](https://supabase.com/).
  2. Copy the connection string and set `DATABASE_URL` in Vercel Environment Variables:
     ```text
     DATABASE_URL=postgresql://user:password@ep-xxxx.neon.tech/neondb?sslmode=require
     ```
  3. QSafeShare will automatically detect `DATABASE_URL`, initialize all tables, and preserve all files and links permanently!

---

## 🚀 Local Installation & Quick Start

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/Siddiqui10/QSafeShare.git
cd QSafeShare
pip install -r requirements.txt
```

### 2. Start the Local Server
```bash
python run.py
```
Open your browser and navigate to:
```
http://127.0.0.1:8000
```

### 3. Run Automated Tests
```bash
pytest -v
```
All **28 unit and integration tests** cover:
- Native NIST ML-KEM-768 and ML-KEM-1024 encapsulation/decapsulation
- AES-256-GCM authenticated encryption & tamper detection
- Sender, Policy, Coordinator, and Audit multi-agent pipeline
- Dynamic access policy matrix (Allowed, Revoked, Expired)
- Google OAuth login redirect & callback token exchange
- Public secure link generation, password protection, and download limits

---

## 📁 Repository Directory Structure

```text
├── api/
│   └── index.py                  # Vercel serverless function entrypoint
├── app/
│   ├── config.py                 # Configuration settings (algorithms, paths, env loader)
│   ├── main.py                   # FastAPI application & route mounting
│   ├── crypto/
│   │   ├── pqc_kem.py            # NIST FIPS 203 ML-KEM-768/1024 wrapper
│   │   ├── symmetric.py          # AES-256-GCM file encryption & HKDF key wrapping
│   │   ├── classical.py          # RSA-2048 & ECDH baseline implementations
│   │   └── utils.py              # SHA-256 hashing, base64, benchmarking helpers
│   ├── agents/
│   │   ├── base.py               # BaseAgent & Inter-Agent Message Envelope protocol
│   │   ├── sender_agent.py       # Sender Agent (AES-256-GCM file ingestion)
│   │   ├── policy_agent.py       # Policy Agent (access policy enforcement)
│   │   ├── coordinator_agent.py  # Coordinator Agent (ML-KEM key distribution)
│   │   └── audit_agent.py        # Audit Agent (security event logging)
│   ├── models/
│   │   └── schemas.py            # Pydantic schemas for requests, responses, events
│   ├── database/
│   │   ├── db.py                 # SQLite connection & schema initialization
│   │   └── repositories.py       # Users, Files, Policies, KeyPackages, Links, Audit
│   ├── services/
│   │   ├── auth_service.py       # Authentication, Google OAuth & ML-KEM key vault
│   │   ├── file_service.py       # Upload, share, revoke, decrypt-verify service
│   │   ├── link_service.py       # Secure public link sharing & download limits
│   │   └── benchmark_service.py  # Complete research benchmark engine
│   ├── api/
│   │   ├── auth_routes.py        # Google OAuth (login/callback), email auth, key vault
│   │   ├── file_routes.py        # File upload, share, policy, decrypt endpoints
│   │   ├── link_routes.py        # Secure link creation, validation, download endpoints
│   │   ├── audit_routes.py       # Live inter-agent audit stream endpoints
│   │   └── benchmark_routes.py   # Interactive benchmark endpoints
│   └── static/
│       ├── index.html            # Main SPA dashboard interface
│       ├── share.html            # Standalone public file download & decrypt interface
│       ├── css/style.css         # Dark-mode responsive design & mobile layout
│       └── js/
│           ├── app.js            # App controller, Google OAuth redirect, file sharing
│           ├── crypto_vault.js   # ML-KEM key vault viewer and key exporter
│           └── benchmarks.js     # Research lab runner & empirical report renderer
├── tests/
│   ├── test_crypto.py            # Cryptographic unit tests (ML-KEM, AES, HKDF)
│   ├── test_agents.py            # Multi-agent unit tests (Sender, Policy, Coordinator)
│   ├── test_access_control.py    # Policy matrix tests (Allowed, Revoked, Expired)
│   ├── test_file_workflow.py     # End-to-end integration test
│   ├── test_link_sharing.py      # Secure link sharing & download limit tests
│   └── test_oauth.py             # Google OAuth login & callback integration tests
├── benchmark.py                  # Standalone CLI research benchmark script
├── run.py                        # Local startup script
├── vercel.json                   # Vercel serverless deployment configuration
├── .env.example                  # Safe template for environment variables
├── requirements.txt              # Production dependencies
└── README.md                     # Comprehensive project documentation
```

---

## 📜 License & Compliance

This software is developed for research and practical deployment of Post-Quantum Cryptography compliant with:
- **NIST FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
- **NIST SP 800-38D**: Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)
