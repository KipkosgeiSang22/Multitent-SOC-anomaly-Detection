# SOC Platform

A full-stack Security Operations Center platform built for Managed Security Service Providers (MSSPs). It handles multi-tenant client management, real-time anomaly detection, and analyst workflows — with a React frontend and a FastAPI backend backed by PostgreSQL.

---

## Overview

The platform is designed around three user roles: **superadmin**, **analyst**, and **client**. Each role gets its own portal with a tailored set of capabilities. Superadmins manage the full environment — onboarding clients, assigning analysts, handling payments. Analysts investigate events and anomalies, manage detection rules, and interact with Graylog. Clients get a read-only view of their own security posture.

Detection runs in two layers: rule-based (Layer 1) for known patterns like brute force or LOLBin activity, and ML-based (Layer 2) for behavioural anomalies across authentication, account management, and process creation event categories. Models can be retrained per-client and rolled back if a new model performs worse.

---

## Tech Stack

**Backend**
- Python 3.11, FastAPI (async), SQLAlchemy (async), PostgreSQL
- Alembic for migrations
- `python-jose` for JWT, `passlib`/`bcrypt` for password hashing, `pyotp` for TOTP-based MFA
- `slowapi` for rate limiting
- `httpx` for Graylog proxy calls
- `aiosmtplib` for email (password reset)
- M-Pesa Daraja API for payments

**Frontend**
- React 19, Vite
- React Router v7
- Zustand for auth state
- Axios for API calls
- CSS Modules for styling

---

## Project Structure

```
soc_platform/
├── backend/
│   ├── app/
│   │   ├── core/         # Config, security, dependencies, middleware, audit
│   │   ├── db/           # Session, base class, DB init
│   │   ├── models/       # SQLAlchemy ORM models
│   │   ├── routers/      # API route handlers (auth, admin, analyst, client, ...)
│   │   ├── schemas/      # Pydantic request/response schemas
│   │   ├── services/     # Daraja (M-Pesa) service
│   │   └── utils/        # Excel formatter and other utilities
│   └── alembic/          # Database migrations
└── frontend/
    └── src/
        ├── portals/
        │   ├── admin/    # Superadmin portal pages
        │   ├── analyst/  # Analyst portal pages
        │   ├── client/   # Client portal pages
        │   └── shared/   # Shared pages (Graylog, rules, retrain)
        ├── pages/        # Auth pages (login, MFA, password reset)
        ├── components/   # Shared components (PortalShell, ProtectedRoute)
        ├── store/        # Zustand auth store
        └── api/          # Axios instance config
```

---

## Features

**Authentication & Security**
- JWT access tokens (15-minute expiry) + HTTP-only refresh token cookies (7-day, rotated on use)
- TOTP-based MFA (required for analysts)
- Account lockout after 5 failed login/MFA attempts (15-minute lockout)
- Password reset via email with time-limited tokens (SHA-256 hashed at rest)
- Force password change on first login
- Full audit log on every significant action
- Fernet encryption for stored Graylog credentials

**Admin Portal**
- Create and manage clients, analysts, and client users
- Grant/revoke per-analyst permissions (edit rules, retrain models, manage Graylog)
- Configure client Graylog instances
- Manage client subscription status and control ML anomaly visibility per client
- Initiate M-Pesa STK Push payments and view payment history
- Export audit logs and event data to Excel

**Analyst Portal**
- Dashboard with live stats (active clients, today's events, unacknowledged anomalies, open issues)
- View and filter security events across all clients (or scoped by permission)
- Acknowledge anomalies and flag false positives
- Raise, resolve, and track issues tied to specific events
- Manage Layer 1 detection rules (create, update, delete, test against live data)
- Retrain ML models per client/category with preview, job status polling, and rollback
- Graylog proxy — manage inputs, users, dashboards with two-step confirmation for destructive actions
- Threat intelligence (NVD CVEs + OTX indicators)
- Audit log viewer

**Client Portal**
- View their own anomalies (filtered by what the admin has made visible)
- View their own events
- Downloads page

---

## Getting Started

### Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Create a `.env` file in `backend/`:

```env
DATABASE_URL=postgresql+asyncpg://user:password@localhost/soc_db
JWT_SECRET=your-secret-key
FERNET_KEY=your-fernet-key
ADMIN_USERNAME=superadmin
ADMIN_PASSWORD=your-admin-password

# Optional — leave blank to skip in development
NVD_API_KEY=
OTX_API_KEY=
GROQ_API_KEY=
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=

# M-Pesa (Daraja) — optional
DARAJA_CONSUMER_KEY=
DARAJA_CONSUMER_SECRET=
DARAJA_SHORTCODE=
DARAJA_PASSKEY=
DARAJA_CALLBACK_URL=

FRONTEND_ORIGIN=http://localhost:5173
ENVIRONMENT=development
MODEL_BASE_PATH=/path/to/models
```

Run migrations and start the server:

```bash
alembic upgrade head
uvicorn app.main:app --reload
```

The API will be at `http://localhost:8000`. Swagger docs at `/docs`.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

The frontend will be at `http://localhost:5173`.

---

## Environment Notes

- In `development` mode, unhandled exceptions return a full traceback (instead of a generic 500). Set `ENVIRONMENT=production` before deploying.
- If `SMTP_HOST` is not set, password reset links are printed to stdout — useful for local development.
- The `MODEL_BASE_PATH` directory is where trained ML model `.pkl` files are stored and loaded from. Make sure the backend process has read/write access to it.
- Daraja callbacks need to be reachable from M-Pesa's servers, so you'll need a public URL (or a tunnel like ngrok) for local testing.

---

## Database Migrations

```bash
# Create a new migration
alembic revision --autogenerate -m "describe your change"

# Apply migrations
alembic upgrade head

# Rollback one step
alembic downgrade -1
```

---

## API Overview

| Prefix | Description |
|---|---|
| `/auth` | Login, MFA, refresh, logout, password reset |
| `/admin` | User, client, permission, and query management |
| `/analyst` | Events, anomalies, issues, dashboard stats |
| `/client` | Client-facing event and anomaly views |
| `/rules` | Layer 1 rule CRUD and testing |
| `/retrain` | ML model retraining and rollback |
| `/graylog` | Graylog proxy and audit |
| `/payments` | M-Pesa payment initiation and callbacks |
| `/health` | Health check |

---

## License

Private/proprietary. Not for public distribution.
