# 🧪 Test Suite Architecture & Verification Guide (`tests/`)

[![Tests](https://img.shields.io/badge/pytest-115%20passed-brightgreen.svg?style=flat-square&logo=pytest)](.)
[![Python](https://img.shields.io/badge/python-3.13-blue.svg?style=flat-square&logo=python)](pyproject.toml)
[![Architecture](https://img.shields.io/badge/architecture-mirrored%20modular-orange.svg?style=flat-square)](tests)

This directory contains the automated test suite for the **FastAPI Base Foundation**. The suite is structured as a mirrored modular hierarchy following modern pytest industry best practices, testing standards, and zero-regression guardrails.

---

## Table of Contents
1. [Core Testing Philosophy](#1-core-testing-philosophy)
2. [Directory Architecture (Mirrored Structure)](#2-directory-architecture-mirrored-structure)
3. [Shared Test Support & Fixture Layer](#3-shared-test-support--fixture-layer)
   - [`tests/support/`](#testssupport-decoupled-test-utilities)
   - [`tests/conftest.py`](#testsconftestpy-global-fixtures)
4. [Test Markers & Verification Gates](#4-test-markers--verification-gates)
5. [Modular File-by-File Technical Reference](#5-modular-file-by-file-technical-reference)
6. [CLI Execution Guide](#6-cli-execution-guide)
7. [Data Contracts & Payload Reference](#7-data-contracts--payload-reference)
8. [Authoring New Tests & Best Practices](#8-authoring-new-tests--best-practices)

---

## 1. Core Testing Philosophy

The test suite enforces four foundational principles:

1. **Mirrored Domain Isolation:**
   * Test files mirror the exact layout of `src/` (e.g. `src/modules/auth/` → `tests/modules/auth/`).
   * Tests are granularly scoped: auth flows, session hardening, and cookie/CSRF transports reside in distinct, focused modules.

2. **Complete Database Isolation (`sqlite+aiosqlite:///:memory:`):**
   * All persistence tests run against an isolated in-memory SQLite database.
   * **Zero contamination:** Physical development databases (`database.db`) are never read or touched.
   * Tables are created and dropped atomically per test via an autouse fixture.

3. **In-Process ASGI Networking (`httpx.AsyncClient`):**
   * Network interactions run in-process through `ASGITransport(app=app)`.
   * Zero socket binding, zero port collisions, and sub-millisecond roundtrips (the full 115-test suite executes in ~3 seconds).

4. **Decoupled Support Infrastructure:**
   * Modules **never import from `conftest` directly** (avoiding pytest runtime anti-patterns).
   * Shared test utilities, engines, sessionmakers, and anchor paths are exported cleanly from `tests.support`.

---

## 2. Directory Architecture (Mirrored Structure)

```
tests/
├── app/                              # Application lifecycle, UI, & middleware
│   ├── test_error_envelopes.py       # Standard RFC 7807 & custom JSON error envelopes
│   ├── test_health.py                # Liveness (/health) & DB readiness (/health/ready) probes
│   ├── test_input_hardening.py       # Pydantic v2 input stripping & bounds validation
│   ├── test_middleware.py            # Trusted proxy headers, rate limiting, & SEC-17/18 doc guards
│   └── test_ui_workbench.py          # /ui static mounting, asset serving, & SEC-08/09 guards
├── cli/                              # Administrative CLI commands
│   └── test_manage.py                # manage.py create-admin, validation, & SEC-16 headless flags
├── contracts/                        # Architectural release gate contracts
│   └── test_release_gate.py          # RG-01 through RG-15 non-negotiable architectural invariant tests
├── database/                         # Core database behaviors
│   └── test_base_repo.py             # BaseRepository deterministic pagination ordering & filtering
├── migrations/                       # Schema evolution tests
│   └── test_migrations.py           # Single Alembic head verification & alembic check drift detection
├── modules/                          # Domain feature modules
│   ├── audit/                        # Audit trail & logging
│   │   ├── test_audit_db_disabled.py # Zero-breakage fallback when audit logging is disabled
│   │   ├── test_audit_logging.py     # Service methods, context injection, & user event queries
│   │   └── test_audit_model.py       # AuditLog model constraints, repr, & export formatting
│   ├── auth/                         # Authentication & token mechanics
│   │   ├── test_auth_flow.py         # End-to-end registration, login, refresh, & logout
│   │   ├── test_events.py            # UserLoggedIn & UserRegistered event bus emission
│   │   ├── test_password_change.py   # Password change, current password check, & security version bump
│   │   ├── test_session_hardening.py # SEC-02 family fail-closed, replay detection, & CAS revocation
│   │   └── test_transport_and_csrf.py# SEC-01 cookie transport, SEC-03 token stripping, & CSRF guards
│   └── user/                         # User domain & RBAC
│       ├── test_events.py            # UserUpdated & UserDeleted event bus emission
│       ├── test_pagination.py        # Keyset & deterministic offset pagination edge cases
│       ├── test_user_crud.py         # User retrieval, profile update, & deletion operations
│       └── test_user_rbac.py         # Role-based access boundaries (ADMIN vs USER)
├── security/                         # Security & Cryptography
│   ├── test_authorization.py         # Casbin 4-tuple RBAC, wildcard evaluation, & SEC-10 caching
│   ├── test_guards.py                # SEC-15 public registration dynamic guards
│   └── test_security.py              # Argon2id hashing, JWT encoding/decoding, & token type safety
├── settings/                         # Configuration & environment hardening
│   └── test_settings.py              # Production safeguards, key entropy, proxy IP resolution, & SEC-04..07
├── share/                            # Cross-cutting primitives
│   ├── test_event_bus.py             # EventBus async handler execution & exception isolation
│   ├── test_helpers.py               # Deterministic sorting, hashing, and date utilities
│   └── test_rate_limit.py            # In-memory sliding window rate limiter & SEC-14 LRU eviction
├── support/                          # Decoupled test support package (no conftest imports)
│   ├── __init__.py                   # Package marker
│   ├── database.py                   # TEST_DATABASE_URL, test_engine, & TestSessionLocal
│   └── paths.py                      # PROJECT_ROOT, ALEMBIC_INI, & STATIC_DIR anchors
├── conftest.py                       # Global fixtures & dependency injection overrides
├── README.md                         # English test architecture documentation (this file)
└── README_AR.md                      # Arabic test architecture documentation
```

---

## 3. Shared Test Support & Fixture Layer

### `tests/support/` Decoupled Test Utilities

To prevent circular dependencies and comply with modern pytest guidelines prohibiting direct imports from `conftest`, test utilities are encapsulated in `tests/support/`:

* **[`tests/support/database.py`](support/database.py)**:
  * `TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"`
  * `test_engine`: Async SQLAlchemy engine instance configured with `echo=False`.
  * `TestSessionLocal`: Async sessionmaker configured with `expire_on_commit=False` and `autoflush=False`.
* **[`tests/support/paths.py`](support/paths.py)**:
  * `PROJECT_ROOT`: Absolute `Path` to project root.
  * `ALEMBIC_INI`: Absolute `Path` to `alembic.ini`.
  * `STATIC_DIR`: Absolute `Path` to `static/`.

### `tests/conftest.py` Global Fixtures

File: [`tests/conftest.py`](conftest.py)

| Fixture Name | Scope | Description |
|---|---|---|
| `init_test_database` | Function (`autouse=True`) | Creates all SQLAlchemy tables (`BaseModel.metadata.create_all`) before each test runs and drops them (`drop_all`) upon teardown. |
| `db_session` | Function | Yields an active `AsyncSession` bound to the in-memory test database for direct seed data insertions. |
| `client` | Function | Yields an `httpx.AsyncClient` wired to the FastAPI application with `app.dependency_overrides[get_session]` active, cleaning overrides up upon teardown. |
| `make_access_token` | Function | **Factory Fixture** returning an async helper `_make(user_id, security_version=1)` to generate signed JWTs without database roundtrips. |

---

## 4. Test Markers & Verification Gates

The test suite defines and registers strict markers in `pyproject.toml` (`--strict-markers` enabled):

| Marker | Filter Command | Test Count | Scope & Purpose |
|---|---|---|---|
| `release_gate` | `uv run --frozen pytest -m release_gate` | **15 tests** | Verifies non-negotiable architectural release contracts (`RG-01` through `RG-15`). |
| `security_audit` | `uv run --frozen pytest -m security_audit` | **18 tests** | Verifies deep cryptographic and vulnerability invariants (`SEC-01` through `SEC-18`). |
| *All tests* | `uv run --frozen pytest` | **115 tests** | Executes the complete test suite. |

---

## 5. Modular File-by-File Technical Reference

### Core Contracts & System Infrastructure
* **`tests/contracts/test_release_gate.py` (15 tests):**
  * Verifies `RG-01` through `RG-15` architectural requirements: async-first DB sessions, fail-closed Casbin authorization, security version invalidation, replay-resistant token rotation, clean migration head, zero unhandled 500 leaks, and hardened production defaults.
* **`tests/migrations/test_migrations.py` (2 tests):**
  * Asserts Alembic migration tree terminates in exactly one linear head (`6aa8f9bfed61`).
  * Executes `alembic check` to ensure zero drift between Python models and database schemas.
* **`tests/cli/test_manage.py` (3 tests):**
  * Tests administrative account creation CLI (`manage.py create-admin`).
  * Verifies email validation, password strength checks, and headless automated execution via `--password-stdin` (`SEC-16`).

### Security, Cryptography & Settings
* **`tests/security/test_security.py` (4 tests):**
  * Verifies Argon2id password hashing, verification, and rejection of invalid passwords.
  * Verifies JWT access and refresh token encoding, claim structures (`sub`, `jti`, `exp`), and token type mismatch prevention.
* **`tests/security/test_authorization.py` (9 tests):**
  * Verifies Casbin RBAC policy engine evaluation, role inheritance, and wildcard access.
  * Verifies the in-memory policy cache TTL and dynamic invalidation (`SEC-10`).
* **`tests/security/test_guards.py` (1 test):**
  * Verifies dynamic blocking of public registration (`SEC-15`) when `ALLOW_PUBLIC_REGISTRATION=False`.
* **`tests/settings/test_settings.py` (10 tests):**
  * Verifies production safeguards (`SEC-04` through `SEC-07`): rejection of weak secrets, distinct HMAC/signing secrets, wildcard CORS bans, and secure cookie requirements.
  * Verifies trusted proxy IP and CIDR resolution (`resolve_client_ip`).

### Authentication & Sessions
* **`tests/modules/auth/test_auth_flow.py` (8 tests):**
  * Full lifecycle: registration, duplicate rejection, weak password rejection, login, token refresh, replay detection, and single-device logout.
* **`tests/modules/auth/test_session_hardening.py` (5 tests):**
  * Tests `SEC-02` fail-closed family validation (`is_family_active`).
  * Verifies atomic compare-and-swap (CAS) session revocation under concurrent refresh attempts.
  * Verifies dummy password verification timing defense against user enumeration.
* **`tests/modules/auth/test_transport_and_csrf.py` (4 tests):**
  * Verifies `SEC-01` cookie-only transport and double-submit CSRF protection (`X-CSRF-Token`).
  * Verifies `SEC-03` token stripping: refresh tokens are never returned in the JSON payload when `AUTH_TRANSPORT_MODE="cookie"`.
* **`tests/modules/auth/test_password_change.py` (3 tests):**
  * Tests credential updates, verification of current password, and automatic invalidation of all existing sessions via `security_version` increment.

### User Domain & Audit Trail
* **`tests/modules/user/test_user_rbac.py` & `test_user_crud.py` (2 tests):**
  * Tests profile retrieval (`/api/v1/users/me`), updates, deletions, and administrative privilege boundaries.
* **`tests/modules/user/test_pagination.py` (2 tests):**
  * Tests keyset and deterministic pagination ordering on base repositories.
* **`tests/modules/audit/test_audit_logging.py` & `test_audit_model.py` (9 tests):**
  * Tests audit logging service operations, user-filtered queries, and file export formatting (JSON, TXT, Markdown).
  * Verifies context injection (`client_ip`, `user_agent`, `request_id`) and credential redaction (zero plain-text password leakage).
* **`tests/modules/audit/test_audit_db_disabled.py` (1 test):**
  * Verifies the application operates seamlessly without errors when `AUDIT_LOG_TO_DB=False`.

---

## 6. CLI Execution Guide

All test commands must be run via `uv`:

### Standard Test Run
```bash
uv run --frozen pytest
```

### Verbose Mode with Execution Timing
```bash
uv run --frozen pytest -v
```

### Run Architecture Release Gate Tests Only
```bash
uv run --frozen pytest -m release_gate -v
```

### Run Deep Security Audit Tests Only
```bash
uv run --frozen pytest -m security_audit -v
```

### Run Specific Test Directory or Module
```bash
# Run all authentication tests
uv run --frozen pytest tests/modules/auth/ -v

# Run release gate contract tests
uv run --frozen pytest tests/contracts/test_release_gate.py -v

# Run settings and security tests
uv run --frozen pytest tests/settings/ tests/security/ -v
```

### Run Filtered Tests by Pattern (`-k`)
```bash
uv run --frozen pytest -k "csrf or cookie" -v
uv run --frozen pytest -k "casbin" -v
```

---

## 7. Data Contracts & Payload Reference

### Registration (`POST /api/v1/auth/register`)

#### Success Scenario
* **Request JSON:**
  ```json
  {
    "name": "Basel Developer",
    "email": "basel@example.com",
    "password": "StrongP@ssw0rd!"
  }
  ```
* **Response Status:** `201 Created`
* **Response Body (`UserResponse`):**
  ```json
  {
    "id": 1,
    "name": "Basel Developer",
    "email": "basel@example.com",
    "role": "user",
    "is_active": true,
    "created_at": "2026-11-04T12:00:00Z",
    "updated_at": "2026-11-04T12:00:00Z"
  }
  ```

#### Duplicate Email Rejection
* **Response Status:** `409 Conflict`
* **Response Body (`ErrorResponse`):**
  ```json
  {
    "success": false,
    "error": {
      "code": "USER_ALREADY_EXISTS",
      "message": "User with email 'basel@example.com' already exists.",
      "details": null
    },
    "request_id": "c1f7a4b8..."
  }
  ```

### Login (`POST /api/v1/auth/login`)

#### Success Scenario (Bearer Mode)
* **Response Status:** `200 OK`
* **Response Body (`TokenResponse`):**
  ```json
  {
    "access_token": "eyJhbGciOiJIUzI1NiIsIn...",
    "refresh_token": "eyJhbGciOiJIUzI1NiIsIn...",
    "token_type": "bearer"
  }
  ```

#### Success Scenario (Cookie-only Mode `SEC-03`)
* **Response Status:** `200 OK`
* **Set-Cookie Headers:** `access_token=...; HttpOnly; Secure; SameSite=Lax`, `refresh_token=...; HttpOnly; Secure; SameSite=Lax`
* **Response Body (`TokenResponse`):**
  ```json
  {
    "access_token": null,
    "refresh_token": null,
    "token_type": "bearer"
  }
  ```

---

## 8. Authoring New Tests & Best Practices

When adding new tests, adhere strictly to these architectural guidelines:

1. **Place Tests in the Mirrored Directory:**
   * Adding a feature to `src/modules/billing/`? Place tests in `tests/modules/billing/test_billing_flow.py`.
2. **Never Import from `conftest`:**
   * Use `tests.support.database` for `TestSessionLocal` or `test_engine`.
   * Use `tests.support.paths` for path references.
3. **Use the `make_access_token` Factory Fixture:**
   * When testing endpoints requiring authentication, prefer `await make_access_token(user_id=1)`.
4. **Always Specify Error Messages in `pytest.raises`:**
   ```python
   with pytest.raises(ValidationException, match="must contain at least one uppercase letter"):
       ...
   ```
5. **Use Explicit Parameter IDs:**
   ```python
   @pytest.mark.parametrize(
       ("payload", "expected_code"),
       [
           ({"email": "valid@example.com"}, 200),
           ({"email": "bad-email"}, 422),
       ],
       ids=["valid-email", "malformed-email"],
   )
   ```
6. **Use `monkeypatch` for Configuration Overrides:**
   * Always revert modified settings cleanly using pytest's built-in `monkeypatch` fixture.
