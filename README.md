<div align="center">
  <h1>🚀 Enterprise FastAPI Base Foundation</h1>
  <p>
    <strong>Hardened, asynchronous backend foundation with PyCasbin RBAC, DDD-lite modularity, and zero-trust security.</strong>
  </p>

  <p>
    <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.13+-3776AB.svg?style=flat&logo=python&logoColor=white" alt="Python 3.13+"></a>
    <a href="https://fastapi.tiangolo.com"><img src="https://img.shields.io/badge/FastAPI-0.141+-009688.svg?style=flat&logo=fastapi&logoColor=white" alt="FastAPI 0.141+"></a>
    <a href="https://www.sqlalchemy.org/"><img src="https://img.shields.io/badge/SQLAlchemy-2.0_Async-D71F00.svg?style=flat&logo=sqlalchemy&logoColor=white" alt="SQLAlchemy 2.0 Async"></a>
    <a href="https://casbin.org/"><img src="https://img.shields.io/badge/PyCasbin-RBAC_Engine-0052CC.svg?style=flat" alt="PyCasbin RBAC"></a>
    <a href="https://docs.astral.sh/uv/"><img src="https://img.shields.io/badge/Toolchain-uv-DE5FE9.svg?style=flat" alt="uv Package Manager"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg?style=flat" alt="MIT License"></a>
    <img src="https://img.shields.io/badge/Tests-82%2F82_Passing-brightgreen.svg?style=flat" alt="82/82 Tests Passing">
  </p>

  <p>
    <a href="#-system-architecture">Architecture</a> ·
    <a href="#-key-capabilities">Key Features</a> ·
    <a href="#-quickstart-guide">Quickstart</a> ·
    <a href="#-api-specification">API Spec</a> ·
    <a href="#-administrative-cli">Admin CLI</a> ·
    <a href="#-automated-testing">Testing</a>
  </p>

  <p>
    🌐 <strong><a href="README_AR.md">النسخة العربية (README_AR.md)</a></strong>
  </p>
</div>

---

## 🏛 System Architecture

The foundation employs a **Domain-Driven Design (DDD-lite)** modular monolith pattern combined with the **Orchestrator-Specialist** behavioral contract:

```mermaid
flowchart TD
    Client(["🌐 Client Application / Browser"]) -->|HTTPS Request + Bearer JWT| Main["⚡ FastAPI Application (main.py)"]
    
    subgraph Perimeter ["Perimeter Middleware & Context"]
        Main --> ReqId["Correlation ID Middleware (X-Request-ID)"]
        ReqId --> AuditCtx["AuditContext Extractor (IP, User-Agent, Trace)"]
        AuditCtx --> DepFactory["Declarative Dependency Injection"]
    end
    
    subgraph Security ["Security & Authorization Engine"]
        DepFactory --> JWTGuard["JWT Validator & security_version Check"]
        JWTGuard --> CasbinGuard["require_permission(Resource, Action)"]
        CasbinGuard <-->|Microsecond In-Memory Check| CasbinCache[("⚡ PyCasbin Policy Engine (AsyncEnforcer)")]
        CasbinCache -.->|Cold Start Hydration / Sync| DB_Rules[("casbin_rule (Storage)")]
    end
    
    subgraph Domain ["Domain Modular Layer (DDD-lite)"]
        CasbinGuard --> Router["Router (Orchestrator)"]
        Router --> Service["Domain Service (Maestro)"]
        Service --> BaseRepo["BaseRepository (Specialist CRUD)"]
    end

    subgraph Infrastructure ["Async Persistence & Event Telemetry"]
        BaseRepo --> AsyncEngine[("AsyncEngine (SQLAlchemy 2.0 / aiosqlite / asyncpg)")]
        Service --> EventBus["EventBus (In-Memory Async Dispatcher)"]
        EventBus --> AuditHandler["Audit Event Consumer"]
        AuditHandler --> SinkDB[("Database Sink (audit_logs)")]
        AuditHandler --> SinkFile["File Sink (logs/ Daily Multi-Format)"]
    end

    subgraph OOB ["Out-of-Band Administration"]
        CLI["manage.py CLI"] -->|Direct Async Session| AsyncEngine
        CLI -->|Seed / Grant / Assign| CasbinCache
    end
```

### Declarative API Security in Practice
Endpoints are protected with atomic, readable dependency factories without polluting business logic:

```python
@router.get(
    "",
    response_model=SuccessResponse[list[UserResponse]],
    dependencies=[Depends(require_permission(resource=Resource.USERS, action=Action.READ))],
)
async def list_users(
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(get_current_user),
) -> SuccessResponse[list[UserResponse]]:
    users = await UserService.get_all_users(session=session)
    return SuccessResponse(data=users)
```

---

## 💡 Overview & Why This Foundation?

Building production-ready backend services requires solving complex cross-cutting challenges before writing a single line of business logic: **authentication session invalidation**, **fine-grained role-based access control**, **observable structured audit logging**, **reliable database migrations**, and **safe administrative bootstrapping**.

This repository provides an enterprise-hardened blueprint designed to eliminate architectural debt:
* **Decoupled Authorization:** Moves beyond crude, hardcoded role checks (`if user.role == 'admin'`) into dynamic, resource-action authorization driven by **PyCasbin**.
* **Zero-Trust Token Revocation:** Prevents zombie sessions when passwords change via an atomic `security_version` counter embedded in JWT claims.
* **Separation of Concerns:** Strict adherence to the Orchestrator-Specialist pattern keeps HTTP routers lightweight, domain services cohesive, and database repositories generic and reusable.
* **Asynchronous First:** Built entirely on native `async`/`await` primitives across the network stack, database driver, and policy engine for high concurrency.

---

## ⚡ Key Capabilities

- 🛡️ **Zero-Trust Granular RBAC (PyCasbin):** Sub-millisecond policy evaluation evaluated in-memory with zero database round-trips per request. Supports role inheritance, wildcards (`*`), and user-specific policy overrides.
- 🔐 **Dual-Token Session Lifecycle & Auto-Revocation:** Issues short-lived access tokens (30 minutes) and revocable refresh tokens (30 days). Cryptographic JTI tracking in `refresh_sessions` with state-of-the-art Argon2id password hashing. Immediate global session invalidation on credential update via `security_version`.
- ⚡ **Native Asynchronous Persistence (SQLAlchemy 2.0):** Pure async I/O via `AsyncEngine` and `async_sessionmaker`. Generic `BaseRepository[Model]` provides standardized CRUD operations while supporting both SQLite (`aiosqlite`) and PostgreSQL (`asyncpg`).
- 📜 **Version-Controlled Database Evolution (Alembic):** Standardized constraint naming conventions (`ix_`, `uq_`, `ck_`, `fk_`, `pk_`) eliminate dialect inconsistencies. Zero runtime DDL generation in production with deterministic schema synchronization checks.
- 🕵️ **Multi-Sink Audit Logging & Telemetry:** Event-driven telemetry via in-memory `EventBus`. Simultaneously streams audit records to relational tables and high-speed disk logs in strict NDJSON format. Includes client IP extraction (`X-Forwarded-For`), User-Agent tracking, before/after state diffs, and strict credential redaction (`exclude={"password"}`).
- 📦 **Standardized API Contracts:** Unified Pydantic V2 response envelopes for single objects (`SuccessResponse`), paginated lists (`PaginatedResponse`), and structured error payloads with unique correlation trace IDs (`X-Request-ID`).
- 🧰 **Out-of-Band Administrative CLI (`manage.py`):** Standalone operations CLI to seed baseline permissions, create root administrators, and assign roles without exposing public registration endpoints.

---

## 🛠 Technology Stack

| Layer | Component | Version / Standard | Purpose |
| :--- | :--- | :--- | :--- |
| **Runtime & Toolchain** | [Python](https://www.python.org/) / [uv](https://docs.astral.sh/uv/) | `Python 3.13+` / `uv >= 0.5` | High-performance runtime and deterministic package management |
| **Web Framework** | [FastAPI](https://fastapi.tiangolo.com/) | `>= 0.141.1` | ASGI web routing, dependency injection, and OpenAPI contract generation |
| **Data & Serialization** | [Pydantic V2](https://docs.pydantic.dev/) | `>= 2.13.4` | Boundary schema validation, settings management (`pydantic-settings`) |
| **ORM & Database** | [SQLAlchemy 2.0](https://www.sqlalchemy.org/) | `>= 2.0.52 (Async)` | Async ORM, declarative mapping, and repository abstraction |
| **Database Drivers** | `aiosqlite` / `asyncpg` | `>= 0.22` / `>= 0.31` | High-throughput asynchronous drivers for SQLite and PostgreSQL |
| **Schema Migrations** | [Alembic](https://alembic.sqlalchemy.org/) | `>= 1.19.1` | Asynchronous migration pipeline with automated constraint naming |
| **Policy Engine** | [PyCasbin](https://casbin.org/) | `>= 1.43.0` | In-memory dynamic RBAC/ABAC authorization engine |
| **Cryptography** | [pwdlib[argon2]](https://github.com/frankie567/pwdlib) / [PyJWT](https://pyjwt.readthedocs.io/) | `>= 0.3.1` / `>= 2.13.0` | Argon2id password hashing and HS256 JWT encoding/decoding |
| **Testing** | [pytest](https://pytest.org/) / [httpx](https://www.python-httpx.org/) | `>= 9.1` / `>= 0.28` | Async integration test suite running 64 automated test scenarios |

---

## 🚀 Quickstart Guide

Get the server running locally in under two minutes:

### 1. Prerequisites
Ensure you have Python 3.13+ and [`uv`](https://docs.astral.sh/uv/) installed:
```bash
# Install uv (Windows PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"

# Install uv (Linux / macOS)
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### 2. Clone & Sync Dependencies
```bash
git clone <repository-url>
cd fastapi-base-structure-dev
uv sync
```

### 3. Configure Environment
Initialize the environment configuration file:
```bash
cp .env.example .env
```
*(The default `.env` is pre-configured for local SQLite development and works out of the box).*

### 4. Run Migrations & Seed Baseline Authorization
```bash
# Apply database schema
uv run alembic upgrade head

# Ingest default Casbin authorization policies
uv run python manage.py seed-policies
```

### 5. Launch Development Server
```bash
uv run uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

### 6. Verify Health
```bash
curl http://127.0.0.1:8000/health
# Output: {"status":"ok","version":"1.0.0","environment":"dev"}
```

---

## 📖 API Specification & Interactive Docs

Once running, interactive API documentation is automatically available at:
* **Swagger UI:** [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* **ReDoc:** [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

### Core Endpoints Overview

| Method | Path | Permission Required | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/auth/register` | *Public* | Register a new user account |
| `POST` | `/api/v1/auth/login` | *Public* | Authenticate and obtain Access & Refresh tokens |
| `POST` | `/api/v1/auth/refresh` | *Public (Refresh Token)* | Rotate refresh token and issue fresh access token |
| `POST` | `/api/v1/auth/change-password` | Authenticated | Change password & revoke all active sessions |
| `POST` | `/api/v1/auth/logout` | Authenticated | Revoke active refresh session |
| `GET` | `/api/v1/users/me` | Authenticated | Fetch current authenticated user profile |
| `GET` | `/api/v1/users` | `users:read` | List paginated users with deterministic sorting |
| `GET` | `/api/v1/users/{id}` | `users:read` | Retrieve specific user by ID |
| `GET` | `/api/v1/audit/logs` | `audit:read` | Query structured audit events with filters |
| `GET` | `/api/v1/audit/export` | `audit:export` | Export audit trail as `JSON`, `TXT`, or `MARKDOWN` |
| `GET` | `/health` | *Public* | Liveness and readiness health probe |

---

## 🧰 Administrative CLI (`manage.py`)

The repository includes a dedicated out-of-band CLI tool to manage policies and administrator credentials directly without exposing public HTTP endpoints.

> 📘 **Full Documentation:** See [manage.md](manage.md) for the complete English reference manual, or [manage_ar.md](manage_ar.md) for Arabic.

```bash
# Seed default authorization rules (admin, *, *)
uv run python manage.py seed-policies

# Create initial root administrator (prompts for password securely)
uv run python manage.py create-admin --email "admin@enterprise.io" --name "Root Admin"

# Promote an existing user to admin
uv run python manage.py promote-admin --email "user@enterprise.io"

# Grant permission to a role
uv run python manage.py grant auditor audit read
uv run python manage.py grant auditor audit export

# Bind a role to a user identifier
uv run python manage.py assign-role 5 auditor

# Inspect active permissions and role groupings
uv run python manage.py list-policies

# Revoke permission from a role (requires --force for admin * *)
uv run python manage.py revoke auditor audit export
```

---

## ⚙️ Configuration & Environment Variables

Settings are managed via `pydantic-settings` with automatic type casting, environment override, and production safety guards:

| Variable | Type | Default | Required | Description |
| :--- | :--- | :--- | :--- | :--- |
| `ENVIRONMENT` | `str` | `dev` | No | Runtime mode (`dev`, `test`, `staging`, `pro`). |
| `DATABASE_URL` | `str` | `sqlite+aiosqlite:///./database.db` | **Yes** | Async connection string (`sqlite+aiosqlite://...` or `postgresql+asyncpg://...`). |
| `ACCESS_SECRET_KEY` | `str` | *dev-placeholder* | **Yes** | Cryptographic secret for signing short-lived access tokens. |
| `REFRESH_SECRET_KEY` | `str` | *dev-placeholder* | **Yes** | Cryptographic secret for signing long-lived refresh tokens. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `int` | `30` | No | Lifetime duration of access tokens in minutes. |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `int` | `30` | No | Lifetime duration of refresh tokens in days. |
| `LOG_TO_DB` | `bool` | `true` | No | Enable or disable persisting audit events to the database. |
| `LOG_TO_FILE` | `bool` | `true` | No | Enable or disable writing structured audit logs to daily disk sinks. |
| `LOG_DIR` | `str` | `logs` | No | Destination directory for daily audit log rotation (`.json`, `.txt`, `.md`). |
| `ALLOWED_ORIGINS` | `list[str]` | `["http://localhost:3000", ...]` | No | Permitted CORS origins. Wildcard `*` is strictly blocked when `ENVIRONMENT=pro`. |
| `TRUST_PROXY_HEADERS` | `bool` | `false` | No | Trust reverse proxy headers (`X-Forwarded-For`) for client IP resolution. |
| `TRUSTED_PROXIES` | `list[str]` | `[]` | No | Explicit IP addresses or CIDR blocks authorized as trusted upstream proxies. |

> [!CAUTION]
> When `ENVIRONMENT=pro`, the application validates that secret keys are not set to placeholder strings and that CORS origins do not contain wildcards (`*`). Failure triggers an immediate startup crash to prevent accidental insecure deployments.

---

## 📂 Project Structure

```
fastapi-base-structure/
├── main.py                     # Application factory, lifespan, global middleware & exception handlers
├── manage.py                   # Out-of-band administrative CLI (superusers, policy seeding, role bindings)
├── manage.md                   # Full CLI operation manual (English)
├── manage_ar.md                # Full CLI operation manual (Arabic)
├── pyproject.toml              # Project metadata, dependencies & tool configs (uv managed)
├── alembic.ini                 # Alembic migration engine configuration
├── .env.example                # Documented environment variable template
├── migrations/                 # Asynchronous database migration environment
│   ├── env.py                  # Migration runner with dynamic settings & metadata discovery
│   ├── script.py.mako          # Async revision template
│   ├── README.md               # Migration manual & database purge guide (English)
│   ├── README_AR.md            # Migration manual & database purge guide (Arabic)
│   └── versions/               # Deterministic, version-controlled migration files
├── src/
│   ├── database/               # Asynchronous persistence infrastructure
│   │   ├── base.py             # DeclarativeBase with standardized constraint naming conventions
│   │   ├── base_repo.py        # Generic BaseRepository[Model] (Async CRUD specialist)
│   │   ├── engine.py           # AsyncEngine & connection pool lifecycle manager
│   │   └── session.py          # Asynchronous database session dependency provider
│   ├── exc/                    # Domain exception hierarchy (AppException & standard error codes)
│   ├── modules/                # Self-contained domain modules (DDD-lite)
│   │   ├── auth/               # Authentication, token rotation, sessions & change-password
│   │   │   ├── dependencies.py # get_current_user & require_permission declarative factories
│   │   │   ├── model.py        # RefreshSession ORM entity with JTI tracking
│   │   │   ├── repo.py         # RefreshSessionRepository specialist
│   │   │   ├── router.py       # Authentication HTTP endpoints
│   │   │   ├── schemas.py      # Request/response validation contracts
│   │   │   └── service.py      # Auth business logic maestro
│   │   ├── user/               # User account domain
│   │   │   ├── model.py        # User ORM entity with security_version counter
│   │   │   ├── repo.py         # UserRepository specialist
│   │   │   ├── router.py       # User management endpoints
│   │   │   └── service.py      # User business logic maestro
│   │   └── audit/              # Security audit logging subsystem
│   │       ├── model.py        # AuditLog ORM entity with composite indexes
│   │       ├── repo.py         # AuditLogRepository specialist
│   │       ├── router.py       # Audit query and export endpoints
│   │       ├── formatters.py   # Multi-format export formatters (JSON, TXT, MARKDOWN)
│   │       └── service.py      # Multi-sink audit logger maestro (DB + File Sinks)
│   ├── security/               # Cryptography & dynamic authorization engine
│   │   ├── authorization.py    # AuthorizationService facade wrapping PyCasbin AsyncEnforcer
│   │   └── security.py         # Password hashing (Argon2id) & JWT token encoders
│   ├── settings/               # Environment settings validation (Pydantic Settings)
│   └── share/                  # Shared primitives (Enums, Response Envelopes, EventBus)
│       ├── enum.py             # Roles, Resource, Action, Severity enums
│       ├── event_bus.py        # In-memory asynchronous domain event dispatcher
│       ├── limits.py           # Hard architectural boundary limits & payload bounds
│       └── responses.py        # Standardized SuccessResponse, PaginatedResponse, ErrorResponse
└── tests/                      # Automated test suite (64 test scenarios)
    ├── conftest.py             # Isolated async SQLite fixtures & HTTP test clients
    ├── test_audit_logging.py   # Multi-sink audit telemetry & sanitization tests
    ├── test_auth_flow.py       # Registration, login, rotation & logout lifecycle
    ├── test_casbin_authorization.py # Granular PyCasbin RBAC & wildcard evaluation
    ├── test_health.py          # Liveness and readiness diagnostic probes
    ├── test_input_hardening.py # Validation error sanitization & payload bounds
    ├── test_migrations.py      # Alembic migration linearity & schema drift check
    ├── test_password_change.py # Security version bumping & global session revocation
    ├── test_security.py        # Argon2id cryptography & JWT token mechanics
    ├── test_security_invariants.py # Session isolation & CSRF/replay invariance
    ├── test_settings_and_context.py # Proxy resolution CIDR & settings hardening
    ├── test_user_rbac.py       # User profile access & paginated user queries
    ├── README.md               # Test documentation (English)
    └── README_AR.md            # Test documentation (Arabic)
```

---

## 🧪 Automated Testing

The project maintains **100% test pass rate** with 64 automated test scenarios covering the full API contract, security boundaries, and edge cases against an isolated in-memory SQLite database:

```bash
# Run all tests with concise or verbose output
uv run pytest -q
uv run pytest -v

# Run migration and schema integrity tests
uv run pytest tests/test_migrations.py -v

# Run authorization and Casbin tests
uv run pytest tests/test_casbin_authorization.py -v

# Run password change and session invalidation tests
uv run pytest tests/test_password_change.py -v

# Run audit logging and telemetry tests
uv run pytest tests/test_audit_logging.py -v

# Run full 15/15 Enterprise Release Gate verification suite (RG-01 to RG-15)
uv run pytest tests/test_release_gate.py -v
`

### 🛡️ Enterprise Security Hardening & Release Gate Contracts

| Gate ID | Invariant & Architectural Contract | Defense & Standard |
|---|---|---|
| **RG-01** | Single unified Alembic head with zero schema drift | Idempotent migrations + autogenerate check |
| **RG-02** | Function-scoped transaction boundary (SessionDep) | Eliminates uncommitted response leakage (F01) |
| **RG-03** | Strict JWT profiles (SubjectIntStr, id, sec_ver) | Uniform 401 Unauthorized responses (F02) |
| **RG-04** | Transactional audit file commit hooks (fter_commit) | Rolled back transactions never write success logs (F03) |
| **RG-05** | Refresh token carries and enforces actual security_version | Prevents token reuse across version upgrades (F04, P07) |
| **RG-06** | Immediate access & refresh token revocation on logout | Smart device isolation preserves other sessions (P01) |
| **RG-07** | Ancestor token logout revokes entire lineage family | Mitigates stale ancestor token retention (P02) |
| **RG-08** | Atomic CAS replay detection revokes family immediately | RFC 9700 §4.14.2 token replay protection (P03) |
| **RG-09** | Purge preserves unexpired revoked tombstones | Retains cryptographic evidence for replay detection (P04) |
| **RG-10** | Comprehensive auth lifecycle audit coverage | Correlates 
equest_id, client IP, and outcomes (P05) |
| **RG-11** | Append-only repository immutability enforcement | Audit records cannot be updated or deleted (P06) |
| **RG-12** | User-scoped session family revocation | Eliminates cross-tenant session disruption (P08) |
| **RG-13** | Constant-time async dummy password verification | Mitigates timing attacks on unregistered emails (P09) |
| **RG-14** | Dual-party actor/target tracking with automated redaction | Redacts credentials, secrets, and auth tokens (P10) |
| **RG-15** | Atomic admin governance lock (UPDATE ... WHERE role='admin') | Serializes deactivations & blocks last-admin lockout (P11) |
``

> 📘 **Test Documentation:** See [tests/README.md](tests/README.md) and [tests/README_AR.md](tests/README_AR.md) for detailed test scenarios, contract envelopes, and architectural verification steps.

---

## 🛠 Developer Guide: Adding a New Domain Module

<details>
<summary><strong>Click to expand: 5-Step Guide to Adding a New Domain Module (e.g. Products)</strong></summary>

### Step 1: Create the Module Directory
```bash
mkdir src/modules/products
```

### Step 2: Define the ORM Entity (`src/modules/products/model.py`)
```python
from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column
from src.database.base import BaseModel
from src.database.mixin import DateTimeMixin

class Product(BaseModel, DateTimeMixin):
    __tablename__ = "products"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
```

### Step 3: Create the Repository Specialist (`src/modules/products/repo.py`)
```python
from sqlalchemy.ext.asyncio import AsyncSession
from src.database.base_repo import BaseRepository
from .model import Product

class ProductRepository(BaseRepository[Product]):
    def __init__(self, session: AsyncSession):
        super().__init__(model=Product, session=session)
```

### Step 4: Implement Service Maestro & Router
* Implement business logic in `service.py`.
* Implement HTTP endpoints in `router.py` protected by `require_permission(Resource.PRODUCTS, Action.READ)`.

### Step 5: Register Router and Generate Migration
* Mount the router in `src/modules/__init__.py`.
* Import the `Product` entity in `migrations/env.py`.
* Generate and apply the migration:
  ```bash
  uv run alembic revision --autogenerate -m "add_products_table"
  uv run alembic upgrade head
  ```
</details>

---

## ⚖️ Architectural Notes & Known Limitations

* **Multi-Worker Casbin Policy Synchronization:** The PyCasbin enforcer operates with in-memory policy caching for ultra-fast evaluations. When policies are altered or roles are assigned via `manage.py` while workers are running, worker processes must be reloaded or restarted to synchronize state, until a distributed watcher (e.g., Redis Pub/Sub) is integrated.
* **Audit Log Immutability Guard:** Append-only immutability for audit records is enforced at the repository layer (`AuditLogRepository`). In high-security production deployments, database-level immutability (e.g., database user privilege revocation on `UPDATE`/`DELETE` or append-only SQL triggers) should be enforced directly on the database engine.

---

## 📄 License & Contributing

This project is open-source and released under the [MIT License](LICENSE). Contributions, bug reports, and pull requests adhering to the repository's architectural principles are welcome.
