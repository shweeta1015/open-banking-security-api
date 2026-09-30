# Open Banking Security API

A secure, educational Open Banking REST API and security simulator demonstrating **Fintech Partner API Keys**, **OAuth 2.0 Authorization Code + PKCE delegated user consent**, **RS256-signed JWTs with RFC 7517 JWKS**, **OWASP API Security Top 5 mitigations**, **DPoP-style Proof-of-Possession replay defense**, and **sanitized security audit logging**.

> [!IMPORTANT]
> **Educational Prototype Only**: All customer accounts, balances, and financial transactions are dummy seeded data. This simulator does not connect to real banks or process real customer funds.

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture & Security Flow](#-architecture--security-flow)
- [Key Features](#-key-features)
- [Technologies Used](#-technologies-used)
- [Project Structure](#-project-structure)
- [OWASP API Security Top 5 Mapping](#-owasp-api-security-top-5-mapping)
- [Security Concepts Explained](#-security-concepts-explained)
- [Installation & Setup](#-installation--setup)
- [Environment Variables](#-environment-variables)
- [Running the Application](#-running-the-application)
- [API Endpoints Reference](#-api-endpoints-reference)
- [Example Usage & Requests](#-example-usage--requests)
- [Testing Instructions](#-testing-instructions)
- [Security Limitations](#-security-limitations)

---

## 🌟 Overview

Under modern open banking frameworks (e.g., UK Open Banking, Berlin Group NextGenPSD2, FDX), third-party fintech providers access bank accounts via APIs on behalf of customers. This architecture requires robust defense-in-depth:
- Fintech apps must authenticate themselves (Machine-to-Machine identity).
- Customers must explicitly grant fine-grained delegated consent via OAuth 2.0 PKCE.
- Resource servers must verify cryptographic access tokens statelessly without database bottlenecks.
- Endpoints must protect against Broken Object Level Authorization (BOLA), excessive data exposure, rate exhaustion, and token replay.

This project implements all of these protections in a clean, self-contained Python FastAPI service with an interactive browser dashboard and test suite.

---

## 🏛️ Architecture & Security Flow

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   CLIENT REQUEST                                       │
│                                                                                        │
│  [ X-API-Key: ob_live_... ]              [ Authorization: Bearer <RS256 JWT> ]         │
│  (Fintech Partner Identity)              (Delegated Customer Consent)                  │
└──────────────────┬──────────────────────────────────────────┬──────────────────────────┘
                   │                                          │
                   ▼                                          ▼
┌──────────────────────────────────────┐   ┌─────────────────────────────────────────────┐
│       PARTNER IDENTIFICATION         │   │       STATELESS JWT VERIFICATION            │
│  - Argon2 Key Hash Verification      │   │  - Asymmetric RS256 signature verification  │
│  - Partner Status (Active/Revoked)   │   │  - Cached Public Key from RFC 7517 JWKS     │
│  - Sliding Window Rate Limiting      │   │  - ZERO database query required             │
│    (HTTP 429 & Retry-After)          │   │  - Expiration (exp), Audience, Issuer check │
└──────────────────┬───────────────────┘   └──────────────────┬──────────────────────────┘
                   │                                          │
                   └──────────────────┬───────────────────────┘
                                      │
                                      ▼
                   ┌──────────────────────────────────────┐
                   │       RESOURCE SERVER GATEWAY        │
                   │                                      │
                   │  1. BOLA / IDOR Verification (API1)  │
                   │     Account ID owned by customer &   │
                   │     explicitly granted in consent    │
                   │                                      │
                   │  2. Data Minimization (API3)         │
                   │     Strict Pydantic response filter  │
                   │     (No internal routing/ledger codes│
                   │                                      │
                   │  3. Function Level Auth (API5)       │
                   │     Scope enforcement on endpoints   │
                   │     (payments:write required)        │
                   │                                      │
                   │  4. DPoP Replay Protection           │
                   │     RFC 9449 Proof-of-Possession     │
                   │     JTI sliding anti-replay cache    │
                   └──────────────────┬───────────────────┘
                                      │
                                      ▼
                   ┌──────────────────────────────────────┐
                   │    SANITIZED SECURITY AUDIT LOGS     │
                   │  - Redacts passwords, tokens & keys  │
                   │  - Records auth failures, BOLA blocks│
                   │    and replay attack attempts        │
                   └──────────────────────────────────────┘
```

---

## ✨ Key Features

1. **Partner API Key Management**:
   - Structured keys: `ob_live_<prefix_8chars>_<secret_32chars>`.
   - Stored strictly as Argon2id hashes; prefix used for indexed lookup without table scanning.
   - Constant-time verification prevents timing attacks.
   - Instant key rotation and partner revocation.
2. **OAuth 2.0 PKCE & Delegated Consent**:
   - RFC 7636 Authorization Code Flow with S256 `code_challenge` and `code_verifier`.
   - CSRF state parameter validation and registered redirect URI enforcement.
   - Customer login and interactive consent screen (`/consent`).
   - Single-use authorization codes with expiration and consumption tracking.
3. **RS256 JWT & RFC 7517 JWKS**:
   - 2048-bit RSA keypair auto-generated on startup in `.keys/` (gitignored).
   - Public JWKS served at `/.well-known/jwks.json`.
   - Stateless cryptographic verification using in-memory cached public key (zero database query).
   - Standard claims: `iss`, `sub`, `aud`, `client_id`, `scope`, `consent_id`, `iat`, `nbf`, `exp`, `jti`.
4. **OWASP API Security Protections**:
   - **API1 BOLA/IDOR**: Verifies authenticated customer owns the account AND consent explicitly authorizes that exact resource ID.
   - **API2 Broken Auth**: Cryptographic signature validation, Argon2 password hashing, and PKCE challenge verification.
   - **API3 Excessive Data Exposure**: Strict Pydantic response models omit internal routing numbers and core ledger codes.
   - **API4 Rate Limiting**: Sliding window counter emitting standard `X-RateLimit-*` and `Retry-After` headers.
   - **API5 BFLA**: Scopes enforced on endpoints; read-only tokens cannot execute payments.
5. **DPoP Replay Defense & Idempotency**:
   - RFC 9449 Proof-of-Possession validation (method, URI, freshness, unique JTI).
   - In-memory sliding anti-replay cache rejecting duplicate proofs with `401 Replay Detected`.
   - `Idempotency-Key` caching on payment transfers preventing duplicate execution.
6. **Sanitized Security Audit Logging**:
   - Comprehensive audit logging of authentication failures, consent decisions, and attack attempts.
   - Automatic redaction of sensitive credentials (tokens, passwords, API keys, card numbers).
7. **Interactive Security Dashboard**:
   - Single-page frontend dashboard (`/`) with OAuth simulator, live API explorer, OWASP Attack Playground, and real-time audit log stream.

---

## 🛠️ Technologies Used

- **Backend**: Python 3.11+, FastAPI, Starlette
- **Server**: Uvicorn (ASGI)
- **Database**: SQLite with SQLAlchemy 2.0 ORM
- **Cryptography**: `cryptography` (RSA 2048-bit PKCS#8), `pyjwt[crypto]` (RS256)
- **Password & Key Hashing**: `argon2-cffi` (Argon2id password hashing)
- **Configuration & Validation**: `pydantic` v2, `pydantic-settings`, `python-dotenv`
- **Testing**: `pytest`, `fastapi.testclient.TestClient`, `httpx`
- **Frontend**: HTML5, CSS3 (responsive dark fintech theme), Vanilla JavaScript

---

## 📁 Project Structure

```
open-banking-security-api/
├── .env.example                 # Example configuration template (safe placeholders)
├── .gitignore                   # Excludes .env, .keys/, databases, caches, logs
├── requirements.txt             # Locked project dependencies
├── README.md                    # Comprehensive documentation and setup guide
├── app/
│   ├── __init__.py
│   ├── main.py                  # FastAPI application factory, middleware, static mounts
│   ├── config.py                # Pydantic BaseSettings environment configuration
│   ├── database.py              # SQLAlchemy engine, session maker, get_db dependency
│   ├── models.py                # ORM models (Partner, Customer, Account, Transaction, etc.)
│   ├── schemas.py               # Pydantic request/response schemas with data minimization
│   ├── seed.py                  # Database seeder with dummy partner, Alice, and Bob
│   ├── security/
│   │   ├── __init__.py
│   │   ├── api_key.py           # API key generation, Argon2 hashing, constant-time validation
│   │   ├── crypto.py            # RSA keypair generation, PEM loading, RFC 7517 JWKS
│   │   ├── jwt_handler.py       # RS256 token issuance & zero-DB local verification
│   │   ├── pkce.py              # PKCE S256 code_verifier and code_challenge validation
│   │   ├── dpop.py              # DPoP proof validation & sliding anti-replay cache
│   │   ├── rate_limiter.py      # Sliding window rate limiter with HTTP 429 headers
│   │   └── audit.py             # Structured security audit logger with secret redaction
│   ├── services/
│   │   ├── __init__.py
│   │   ├── banking_service.py   # Banking operations with BOLA and idempotency checks
│   │   ├── oauth_service.py     # OAuth authorize, customer consent, and token exchange
│   │   └── partner_service.py   # Partner registration, key rotation, and revocation
│   └── routes/
│       ├── __init__.py
│       ├── auth_routes.py       # /oauth/authorize, /consent, /token, /.well-known/jwks.json
│       ├── partner_routes.py    # /api/v1/partners/me, rotate-key, revoke
│       ├── banking_routes.py    # /api/v1/accounts, /balances, /transactions, /payments
│       ├── audit_routes.py      # /api/v1/audit/logs
│       └── web_routes.py        # Web routes serving dashboard and consent screen
├── frontend/
│   ├── index.html               # Main security dashboard & OWASP attack playground
│   ├── consent.html             # Dedicated OAuth 2.0 customer consent screen
│   ├── css/
│   │   └── styles.css           # Modern dark-themed fintech dashboard styles
│   └── js/
│       ├── app.js               # Application state, live API explorer, OWASP playground
│       ├── oauth.js             # Client-side PKCE generation and JWT inspection
│       └── audit.js             # Security audit log live stream and rendering
└── tests/
    ├── __init__.py
    ├── conftest.py              # Pytest fixtures, test database isolation, TestClient
    ├── test_api_keys.py         # Partner API key validation, rotation, revocation
    ├── test_oauth_pkce.py       # PKCE flow, customer consent, single-use codes
    ├── test_jwt_jwks.py         # RS256 signature, expiry, tampered JWT, JWKS compliance
    ├── test_bola.py             # OWASP API1 BOLA cross-customer account isolation
    ├── test_data_minimization.py# OWASP API3 Data minimization & API5 BFLA scope enforcement
    ├── test_rate_limiting.py    # OWASP API4 Rate limiting & 429 response headers
    └── test_replay_dpop.py      # DPoP anti-replay cache & idempotency key verification
```

---

## 🛡️ OWASP API Security Top 5 Mapping

| OWASP Threat | Vulnerability Description | Simulator Security Control | Reproducible Pytest |
|---|---|---|---|
| **API1:2023 Broken Object Level Authorization (BOLA / IDOR)** | An attacker alters resource IDs in API paths (e.g. `acc_bob_chk_01`) to view another user's private data. | `BankingService._verify_consent_and_account_access` enforces that the requested `account_id` is both owned by the token's `sub` AND granted in the active consent record. Unmatched access returns safe 404/403. | `tests/test_bola.py::test_cross_customer_account_bola_blocked` |
| **API2:2023 Broken Authentication** | Compromised credentials, tampered JWT signatures, or stolen authorization codes. | 1. Asymmetric RS256 verification using cached RSA 2048 public key rejects tampered tokens.<br>2. Argon2id password and API key hashing.<br>3. PKCE S256 prevents code interception.<br>4. Single-use authorization codes prevent replay. | `tests/test_jwt_jwks.py::test_tampered_jwt_signature_rejected`<br>`tests/test_oauth_pkce.py::test_pkce_verifier_mismatch_rejected` |
| **API3:2023 Broken Object Property Level Authorization / Excessive Data Exposure** | Internal bank infrastructure metadata or unconsented properties leak in API responses. | Response serialization uses strict Pydantic schemas (`AccountSummary`, `TransactionResponse`). Proprietary database fields like `internal_routing_code` and `internal_ledger_ref` are filtered out. Balances require a dedicated `balances:read` scope. | `tests/test_data_minimization.py::test_data_minimization_internal_properties_omitted` |
| **API4:2023 Unrestricted Resource Consumption** | Lack of rate limiting allows API exhaustion, denial of service, or brute force attempts. | `SlidingWindowRateLimiter` enforces per-partner requests-per-minute limits, returning HTTP 429 with `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`, and `Retry-After` headers. | `tests/test_rate_limiting.py::test_rate_limit_threshold_triggers_429` |
| **API5:2023 Broken Function Level Authorization (BFLA)** | A consumer with read-only access calls privileged or state-changing endpoints (e.g., executing money transfers). | `require_scope("payments:write")` dependency validates that the token possesses payment authorization before invoking `POST /api/v1/payments`. Read-only tokens receive HTTP 403 Forbidden. | `tests/test_data_minimization.py::test_bfla_read_only_token_cannot_initiate_payments` |

---

## 🔒 Security Concepts Explained

### 1. Why a Plain Bearer Token Alone Cannot Prevent Replay
A plain Bearer token functions like cash: whoever possesses the token can present it. If an attacker intercepts a bearer token (via a compromised proxy, server log, or browser leak), the attacker can replay that token repeatedly until its expiration (`exp`).

**Our DPoP Mitigation:**
- The client binds requests to a cryptographic Proof-of-Possession header (`X-DPoP-Proof`).
- The proof includes the HTTP method (`htm`), the target URI path (`htu`), a short-lived timestamp (`iat`), and a unique proof ID (`jti`).
- The server checks timestamp freshness (rejecting drift > 60s) and maintains an in-memory anti-replay cache of recent JTIs.
- If an attacker intercepts and replays the same proof header, the server rejects it with **HTTP 401 Replay Detected**.

### 2. Stateless JWT Validation vs. Immediate Revocation Trade-off
- **Stateless Verification:** In distributed systems, querying a database for every API request creates a bottleneck. Using RS256 with a public JWKS allows resource servers to cryptographically verify token authenticity in microseconds without database roundtrips.
- **Revocation Challenge:** Because the token is self-contained and valid until `exp`, revoking user consent does not automatically invalidate an in-flight JWT without state.
- **Our Implementation:** Tokens have short lifespans (15 minutes). For high-risk operations (such as payments or consent revocation), the server checks the `Consent` record status.

### 3. API Keys Are Not User Consent
Partner API keys authenticate the **fintech application** (machine-to-machine identity), enabling client identification, partner revocation, and rate limiting. They **never** substitute for user consent. Customer financial data is only accessible after an explicit OAuth 2.0 PKCE consent grant by the account owner.

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.11+
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/shweeta1015/open-banking-security-api.git
cd open-banking-security-api
```

### 2. Create and Activate Virtual Environment
```bash
# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment
```bash
# Copy template configuration
cp .env.example .env
```

---

## ⚙️ Environment Variables

The application is configured using `.env` (managed via Pydantic `BaseSettings`):

| Variable | Description | Default |
|---|---|---|
| `PROJECT_NAME` | Service name | `"OpenBankingSecurityAPI Simulator"` |
| `API_V1_PREFIX` | Prefix for API routes | `"/api/v1"` |
| `ENVIRONMENT` | Environment mode | `"development"` |
| `DEBUG` | Enable debug logging | `True` |
| `DATABASE_URL` | SQLite connection string | `"sqlite:///./open_banking_sim.db"` |
| `RSA_PRIVATE_KEY_PATH` | Server-side private key path | `"./.keys/private_key.pem"` |
| `RSA_PUBLIC_KEY_PATH` | Server-side public key path | `"./.keys/public_key.pem"` |
| `RSA_KEY_ID` | Key identifier (`kid`) in JWKS | `"obs-key-2026-v1"` |
| `JWT_ISSUER` | JWT `iss` claim | `"https://auth.simulator.openbanking.local"` |
| `JWT_AUDIENCE` | JWT `aud` claim | `"https://api.simulator.openbanking.local"` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Token validity lifetime | `15` |
| `AUTH_CODE_EXPIRE_SECONDS` | Single-use auth code lifetime | `300` |
| `DEFAULT_PARTNER_RATE_LIMIT` | Max requests per minute | `60` |
| `DPOP_PROOF_MAX_AGE_SECONDS` | Max allowed clock skew for DPoP | `60` |

---

## 💻 Running the Application

Start the local server with hot reloading:
```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Then open your browser:
- **Interactive Security Dashboard**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive Swagger Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Public JWKS Endpoint**: [http://127.0.0.1:8000/.well-known/jwks.json](http://127.0.0.1:8000/.well-known/jwks.json)

---

## 🎯 Demo Credentials (Seeded)

| Role | Username / ID | Password / API Key | Consented Resources |
|---|---|---|---|
| **Partner** | `fintech_partner_demo` | `ob_live_demo1234_supersecretpartnerkey987654321` | Demo Fintech Analytics Ltd |
| **Customer 1** | `alice` | `AliceSecurePass2026!` | Checking (`acc_alice_chk_01`), Savings (`acc_alice_sav_02`) |
| **Customer 2** | `bob` | `BobSecurePass2026!` | Checking (`acc_bob_chk_01`) |

---

## 📡 API Endpoints Reference

### Public & Metadata
- `GET /.well-known/jwks.json` - RFC 7517 Public Key Set exposing RS256 public key.
- `GET /health` - Service health status.

### Partner Management (`X-API-Key` protected)
- `POST /api/v1/partners/register` - Register a new fintech partner organization.
- `GET /api/v1/partners/me` - Retrieve current partner identity and rate limit tier.
- `POST /api/v1/partners/{client_id}/rotate-key` - Rotate partner API key immediately.
- `POST /api/v1/partners/{client_id}/revoke` - Revoke partner access.

### OAuth 2.0 PKCE & Consent
- `GET /oauth/authorize` - Initiate authorization flow with PKCE challenge.
- `POST /oauth/consent` - Customer authentication and resource delegation screen.
- `POST /oauth/token` - Exchange authorization code + `code_verifier` for RS256 JWT.
- `POST /oauth/revoke` - Revoke customer consent record.
- `GET /oauth/demo-customers` - Helper listing demo customers and accounts.

### Banking APIs (Bearer Token & Scope protected)
- `GET /api/v1/accounts` - List consented accounts (requires `accounts:read`).
- `GET /api/v1/accounts/{id}` - Account summary with BOLA check (requires `accounts:read`).
- `GET /api/v1/accounts/{id}/balances` - Account balance (requires `balances:read`).
- `GET /api/v1/accounts/{id}/transactions` - Transactions history (requires `transactions:read`).
- `POST /api/v1/payments` - Simulated transfer (requires `payments:write`, DPoP proof, and `Idempotency-Key`).

### Security Audit
- `GET /api/v1/audit/logs` - Query sanitized security event stream.

---

## 🧪 Testing Instructions

Run the comprehensive automated test suite with pytest:
```bash
python -m pytest -v
```

All 31 unit and integration tests execute against an isolated test database and verify:
- Partner API key hashing, validation, rotation, and revocation (`test_api_keys.py`)
- OAuth 2.0 PKCE challenge validation, single-use codes, and consent checking (`test_oauth_pkce.py`)
- RS256 cryptographic signature, expiry, tampered tokens, and JWKS RFC 7517 compliance (`test_jwt_jwks.py`)
- OWASP API1 BOLA cross-customer account isolation (`test_bola.py`)
- OWASP API3 Data minimization & API5 BFLA scope enforcement (`test_data_minimization.py`)
- OWASP API4 Sliding window rate limiting and HTTP 429 headers (`test_rate_limiting.py`)
- DPoP Proof-of-Possession replay detection and idempotency key caching (`test_replay_dpop.py`)

---

## ⚠️ Security Limitations

1. **Local Prototype**: Designed specifically for security education, testing, and architecture demonstration.
2. **In-Memory Rate Limiting**: The sliding-window rate limiter and DPoP replay cache run in-memory within the single process. In distributed production environments, these must be backed by a clustered shared store such as Redis or Dragonfly.
3. **Database**: Uses SQLite for portability. Production banking systems require enterprise distributed databases (e.g. PostgreSQL) with encryption-at-rest.
4. **Key Storage**: RSA keys are stored on the local filesystem in `.keys/`. Production deployments should use a dedicated Hardware Security Module (HSM) or cloud KMS (e.g. AWS KMS, Google Cloud KMS, Azure Key Vault).
