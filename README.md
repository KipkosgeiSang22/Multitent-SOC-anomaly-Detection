# SOC Platform

A commercial, multi-tenant Security Operations Center (SOC) monitoring platform built for Managed Security Service Providers (MSSPs). It lets a single analyst team watch over 15+ client organizations , banks, SACCOs, and enterprises , from one interface, while each client organization's users log in to a fully isolated portal to view, confirm, and raise issues on their own security events.

The platform is in active migration from a Streamlit proof-of-concept to a production-grade FastAPI backend and React frontend. The Graylog integration, anomaly detection engine, and client portal are production-ready. Wazuh, Splunk, Elastic, and Microsoft Sentinel adapters are scaffolded and in active development.

---

## Table of Contents

1. [What This Platform Does](#what-this-platform-does)
2. [Architecture Overview](#architecture-overview)
3. [Multi-SIEM Design and Event Normalization](#multi-siem-design-and-event-normalization)
4. [Anomaly Detection Pipeline](#anomaly-detection-pipeline)
5. [Threat Intelligence Layer](#threat-intelligence-layer)
6. [Event Grouping and Client Transparency](#event-grouping-and-client-transparency)
7. [Known Limitations and Planned Improvements](#known-limitations-and-planned-improvements)
8. [Roles and Access Model](#roles-and-access-model)
9. [Project Structure](#project-structure)
10. [Prerequisites](#prerequisites)
11. [Environment Variables](#environment-variables)
12. [Database Setup](#database-setup)
13. [Running the Backend](#running-the-backend)
14. [Running the Frontend](#running-the-frontend)
15. [Running the Scheduler Processes](#running-the-scheduler-processes)
16. [ML Models](#ml-models)
17. [Deployment Considerations](#deployment-considerations)
18. [Contributing](#contributing)
19. [License](#license)

---

## What This Platform Does

Client organizations generate security event logs that flow into a SIEM (currently Graylog; others in progress). This platform sits on top of any supported SIEM, pulling events every three minutes, normalizing them into a canonical intermediate schema before storage, grouping repetitive events within two-hour windows, and running them through a multi-layer anomaly detection engine.

Layer 1 is deterministic and rule-based. Layer 2 is a per-client, per-category Isolation Forest that scores events against each client's own behavioral baseline. A third layer , threat intelligence correlation , cross-references collected IOCs (IPs, file hashes, domains) against a continuously updated threat intelligence database. All three layers feed into a unified anomaly surface that SOC analysts triage and that client users can optionally be given visibility into.

The client portal is not an investigation tool. Client users are not expected to hunt threats , they confirm events they recognize as legitimate activity within their organization and raise issues on anything that looks wrong. This reduces unnecessary back-and-forth between the MSSP and its clients, keeps clients informed without overwhelming them, and builds an explicit confirmation trail that analysts can see. Client users never have access to anomaly scores, detection logic, or any data belonging to another organization.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                         React Frontend                            │
│   /client/*    (client portal , event review and confirmation)   │
│   /analyst/*   (SOC analyst dashboard , full triage interface)   │
│   /admin/*     (superadmin , user, client, permission mgmt)      │
└──────────────────────────┬───────────────────────────────────────┘
                           │ JWT (access token in memory only;
                           │ refresh token in httpOnly cookie)
┌──────────────────────────▼───────────────────────────────────────┐
│                       FastAPI Backend                             │
│   Auth · Events · Anomalies · Retrain · Rules · Payments         │
│   PostgreSQL (asyncpg) + Row-Level Security                      │
└───────┬────────────────────┬───────────────────────┬─────────────┘
        │                    │                       │
┌───────▼──────┐    ┌────────▼──────┐      ┌────────▼──────┐
│log_collector │    │anomaly_       │      │threat_        │
│.py           │    │engine.py      │      │intel.py       │
│(every 3 min) │    │(every 5 min,  │      │(every 6 hr)   │
│              │    │ offset 1 min) │      │               │
└───────┬──────┘    └────────┬──────┘      └────────┬──────┘
        │                    │                       │
┌───────▼──────────┐ ┌───────▼──────┐    ┌──────────▼────────────┐
│  SIEMAdapter     │ │  ML Models   │    │  NVD · OTX · RSS      │
│  (factory.py)    │ │  .pkl per    │    │  MITRE ATT&CK         │
│                  │ │  client ×    │    │  Claude API            │
│  ✅ Graylog      │ │  category    │    │  (summarization)       │
│  🔧 Wazuh        │ └──────────────┘    └───────────────────────┘
│  🔧 Splunk       │
│  🔧 Elastic      │
│  🔧 Sentinel     │
└──────────────────┘
        │
        ▼
Normalization → canonical event schema → operational_events (PostgreSQL)
```

The three scheduler processes are deliberately independent , a crash in the anomaly engine never stops log collection, and a slow threat intel fetch never delays either. Each writes its own heartbeat to `scheduler_status` after every cycle, which the analyst dashboard displays as a live health panel.

<img width="1913" height="922" alt="image" src="https://github.com/user-attachments/assets/05f40572-ed73-499e-bbf2-ec3162528138" />


---

## Multi-SIEM Design and Event Normalization

This is one of the more architecturally important aspects of the platform, and it is worth explaining clearly.

### The Adapter Pattern

All SIEM communication goes through an abstract `SIEMAdapter` base class defined in `backend/app/siem/base.py`. The `factory.py` module reads `clients.siem_type` from the database at runtime and returns the correct adapter instance for each client. Adding a new SIEM requires only a new adapter class that implements the interface , nothing in the log collector, anomaly engine, or any other part of the platform needs to change.

```
factory.py
  └── clients.siem_type == "graylog"   → GraylogAdapter    ✅ implemented
  └── clients.siem_type == "wazuh"     → WazuhAdapter       🔧 stub (stubs.py)
  └── clients.siem_type == "splunk"    → SplunkAdapter      🔧 stub (stubs.py)
  └── clients.siem_type == "elastic"   → ElasticAdapter     🔧 stub (stubs.py)
  └── clients.siem_type == "sentinel"  → SentinelAdapter    🔧 stub (stubs.py)
```

The four non-Graylog adapters are fully instantiable but every method raises `NotImplementedError` with the adapter name in the message , they will never silently return empty data, which would be indistinguishable from a quiet network.

Each adapter has its own native query language. The Graylog adapter uses Lucene query syntax, passed as the `graylog_query` field in `client_queries`. When the other adapters are implemented, their `client_queries` rows will carry queries in the appropriate native language. The `query_name` field is what the rest of the platform uses , the native query string is opaque to everything outside the adapter.

### Normalization Before Storage

Raw SIEM responses differ significantly in field names, data types, nesting, and timestamp formats depending on the source. Before any event is written to `operational_events`, the adapter normalizes it into a canonical intermediate structure:

All timestamps are converted from their native format and timezone to `Africa/Nairobi (EAT)` using `pytz`. This is done at collection time, not at query time, so the database always holds EAT timestamps regardless of which SIEM produced the event. Field names from each SIEM's native schema are mapped to a consistent set of keys. Graylog internal metadata fields (`_id`, `gl2_message_id`, `gl2_source_input`, `streams`, `source`) are stripped during normalization , they carry no analytical value and would pollute frequency-based features. The normalized event payload is stored in the `fields` JSONB column of `operational_events`, which is treated as the raw source of truth.

### Why JSONB for Raw Fields

JSONB is used for the `fields` column because named queries across different clients and SIEMs return different field sets. An "Account Lockouts" query returns EventID, TargetUserName, and IpAddress. An "External IP Activity" query returns different fields entirely. Rather than building a wide, sparse table with hundreds of nullable columns, the varying fields are stored as JSONB per row.

However, JSONB is not used for direct ML feature extraction. The anomaly engine reads the JSONB fields only to populate the fixed-schema typed tables (`auth_events`, `account_events`, `process_events`). Those typed tables have explicit, typed columns and are what the Isolation Forest models and Layer 1 rules actually consume. This separation means JSONB serves its purpose as a flexible raw store without the consistency and performance problems that come from running ML feature pipelines directly against it.

<img width="1845" height="933" alt="image" src="https://github.com/user-attachments/assets/1b168a6d-e307-458d-aadb-dac7337dea79" />


### Wazuh (In Progress)

The `WazuhAdapter` class is instantiable but all interface methods currently raise `NotImplementedError`. The adapter will connect to the Wazuh REST API, normalize its alert schema to the canonical structure, and map Wazuh's rule IDs to the appropriate ML categories.

 

### Splunk (In Progress)

`SplunkAdapter` follows the same pattern, with SPL as its native query language.

 

### Elastic and Microsoft Sentinel (Planned)

`ElasticAdapter` and `SentinelAdapter` exist as stubs. Timeline TBD.

---

## Anomaly Detection Pipeline

Events arrive in `operational_events` from the log collector. The anomaly engine reads from there every five minutes , it never calls any SIEM API itself, and it never modifies confirmation data or client-written issue text.

### Layer 1 , Deterministic Rules

Each client has an independent rule set stored in `layer1_rules` as structured JSONB. The anomaly engine interprets the JSONB conditions at runtime , there is no Python code embedded in rules, which means rules can be edited, audited, and version-controlled without any code deployment.

Default rules seeded for every new client cover brute force (more than 5 authentication failures within 5 minutes from the same source IP), privilege escalation (privilege assignment or group membership events originating from non-administrative accounts), suspicious process execution (command lines matching LOLBin patterns, base64-encoded PowerShell, or administrative account enumeration), off-hours activity (events outside 07:00–19:00 EAT), and rapid account manipulation (account creation followed immediately by deletion).

Rules apply to the normalized event data in the typed tables, not to the raw JSONB. Analysts with the `can_edit_layer1_rules` permission can create, modify, or disable rules through a form-based UI. Each save writes a full before/after JSONB snapshot to the audit log. A dry-run mode lets an analyst preview which events in the last 24 hours would have been flagged before committing the rule.

It is worth noting that the current default rule set references Windows Event IDs because Windows is the environment where this has been deployed first. The rule engine itself is not Windows-specific , rules operate on normalized field values from the typed tables, and when other adapters are live, their events will populate the same typed tables and the same rules will apply without modification.
<img width="1897" height="928" alt="image" src="https://github.com/user-attachments/assets/22938445-938b-42e0-8cb8-02f9179588fc" />

### Layer 2 , Isolation Forest (Behavioral Baseline)

Three Isolation Forest models run per client, separated by event category: `AuthenticationEvents` (login successes, failures, session opens, explicit credential use, special privilege assignments), `AccountManagementEvents` (account creation, deletion, modification, group membership changes), and `ProcessCreationEvents` (process start and stop events).

The separation matters because authentication behavior and process creation behavior have fundamentally different statistical distributions. A single model across all event types would produce meaningless anomaly scores.

<img width="1872" height="921" alt="image" src="https://github.com/user-attachments/assets/b89b948c-a735-424e-8256-23da671ff226" />


**Feature Engineering**

Two functions handle feature extraction and must run identically at training time and at scoring time. `add_time_features()` extracts Hour (0–23), DayOfWeek (0–6), and IsWeekend (bool) from the normalized EAT timestamp. This is why timestamp normalization to EAT at collection time is non-negotiable , if timestamps were stored in UTC and the timezone conversion happened at feature extraction time, any change to that conversion logic between training and inference runs would silently produce different feature values and invalidate the model.

`apply_freq_map()` converts high-cardinality text columns (TargetUserName, IpAddress, CommandLine, SubjectUserName) into frequency floats , the proportion of times that value appeared in the training window. This encodes behavioral rarity without requiring one-hot encoding of unbounded categorical spaces. A new employee's username has a low frequency score; a service account that authenticates thousands of times daily has a high one.

**Feature Schema Consistency**

One of the real risks in any ML pipeline that runs continuously is silent feature drift , a change upstream that changes what the model receives at inference time without the model being retrained. This platform addresses it by storing engineered features explicitly in the typed tables at scoring time (the anomaly engine writes `hour`, `day_of_week`, `is_weekend`, `target_username_freq`, `ip_address_freq`, and so on as concrete typed columns), recording the feature column list used for each training run in `ml_models.feature_columns` (JSONB), and running the same `add_time_features()` and `apply_freq_map()` functions from the same module at both training and inference, imported from a shared location rather than duplicated.

Feature schema versioning , where the feature set itself is given a version identifier that is checked before scoring , is a planned improvement documented in the [Known Limitations](#known-limitations-and-planned-improvements) section.

**Scoring and Model Storage**

The engine calls `model.decision_function()` to produce anomaly scores. Lower scores indicate higher abnormality. Per-category thresholds determine what score triggers an anomaly write.

Models are stored at `MODEL_BASE_PATH/{client_id}/{category}.pkl`. Before overwriting on retrain, the existing model is copied to `.bak.pkl`. Analysts with `can_retrain_models` permission can review scored events, mark false positives for inclusion in retraining data, exclude confirmed true positives, and trigger a retrain as a background task. After retraining, a score distribution comparison between old and new models is shown before the analyst accepts or rolls back.

If a model file is missing or corrupt at runtime, the engine logs a critical error, skips Layer 2 for that client in that cycle, and continues processing other clients. Layer 1 rules still run and `analyzed_at` is still set. One client's model failure never crashes the engine.

<img width="1542" height="632" alt="image" src="https://github.com/user-attachments/assets/7e7893ca-f319-4dec-8a91-81bebccabdd5" />


---

## Threat Intelligence Layer

`threat_intel.py` runs every six hours and collects from NVD (National Vulnerability Database) , CVEs from the last 6 hours, AlienVault OTX , threat pulses from the last 6 hours, RSS feeds (BleepingComputer, The Hacker News, Dark Reading), and the MITRE ATT&CK enterprise attack pattern catalogue, downloaded as `enterprise-attack.json`.

Articles and advisories longer than 500 characters are summarized to 2–3 sentences by the Claude API (`claude-haiku-4-5`) before storage. This keeps the threat intel feed scannable for analysts without losing the source link for those who want the full detail.

Each collected item carries an `iocs` JSONB column containing extracted IPs, file hashes, and domains. A GIN index on this column makes cross-referencing fast.

The anomaly engine cross-references IPs and hashes from incoming events against `threat_intel.iocs`. A match is written to the `anomalies` table as `anomaly_type = ThreatIntelMatch`. This functions as an emerging Layer 3 , it is not a scoring model and does not produce a continuous anomaly score, but it provides high-confidence signal when an event's network indicators match known malicious infrastructure or malware signatures. The threat intelligence layer is still expanding and this cross-reference logic will be refined as more IOC sources are added.
<img width="1852" height="923" alt="image" src="https://github.com/user-attachments/assets/cf0ab2ce-09cc-4ec7-8b91-d1172fe4b995" />

---

## Event Grouping and Client Transparency

### Why Grouping Exists

A client organization's domain controller might log hundreds of authentication events per hour during normal business activity. Presenting every individual event row to a client user is not useful , it overwhelms them and makes it harder, not easier, to spot genuine anomalies. The grouping logic addresses this directly.

### How It Works

When the log collector upserts events into `operational_events`, it computes a `group_key` , a hash of all non-timestamp fields for that event. Events sharing the same `group_key` within a two-hour rolling window are collapsed into a single display row. The row stores a `time_summary` containing the first, middle, and last occurrence timestamps, making it clear that this is a recurring event rather than a one-time occurrence.

If a new occurrence arrives with the same `group_key` but its timestamp is more than two hours after the last event in the existing group, it becomes a new row and requires its own confirmation from the client.

### What the Client Portal Actually Is

The client portal is a transparency and communication layer, not an investigation console. Client users see their own organization's events organized into named query tabs (Account Lockouts, External IP Activity, Successful RDP Logons, and so on). They can confirm events they recognize as expected activity, and they can raise issues on anything that looks wrong.

Anomaly scores, detection thresholds, ML model details, and Layer 1 rule logic are never exposed to client users. If the superadmin enables anomaly visibility for a client, that client can see which of their events were flagged , not why the algorithm flagged them or what score was assigned.

 <img width="1877" height="860" alt="image" src="https://github.com/user-attachments/assets/e14904bb-966e-4aa1-85b5-57e73fbfdd3b" />


---

## Known Limitations and Planned Improvements

This section exists because an honest system document is more useful than one that omits known gaps. These are real limitations, not hypothetical edge cases.

**Feature schema versioning is not yet implemented.** The `ml_models.feature_columns` column records what features a model was trained on, but there is no automated check at inference time that verifies the incoming feature vector matches the schema the loaded model expects. If a normalization change or adapter update silently changes the features available for a client, the model will score against the wrong schema without raising an error. The planned fix is explicit versioned feature schemas , a version identifier attached to each model file and checked at scoring time before the model is used.

**The correlation window is fixed at two hours.** Slow attacks , lateral movement that unfolds over hours or days, low-and-slow credential stuffing, long dwell-time intrusions , will not be correlated into a single group by the current logic. Adaptive or sliding correlation windows, potentially driven by the anomaly score of the first event in a sequence, are on the roadmap.

**JSONB is not currently used for direct ML queries**, which is correct, but there is a risk that shortcuts will emerge as the platform grows. Any future contributor who reaches into the `fields` JSONB column to build an ML feature is introducing the exact consistency and performance problems the typed table separation is designed to prevent. The canonical flow is: `fields` JSONB → normalization → typed table → ML features. Contributions that shortcut this will not be accepted.

**Frequency maps are computed per training run, not maintained as a rolling store.** `apply_freq_map()` builds frequency floats from the data available at training time. At inference time, new values not seen during training (a new employee's username, a new server's IP) receive a frequency of zero or a low default. This is correct behavior, but it means the model's sensitivity to new principals decays between retraining runs. A lightweight feature store that maintains rolling frequency counts between retrains would make this more robust.

**Threat intelligence cross-referencing (Layer 3) is early-stage.** IOC matching currently covers IPs and hashes. Domain-based matching, MITRE ATT&CK technique tagging on events, and confidence scoring for IOC matches are planned.

---

## Roles and Access Model

**Superadmin** has full platform access with no restrictions. They create and manage analyst accounts, create and manage client accounts and their users, toggle anomaly visibility per client, manage subscriptions, and grant or revoke elevated permissions from analysts. Every permission grant is logged with a reason, the identity of who granted it, and a timestamp.

**SOC Analyst** can view all clients' events and anomalies, acknowledge anomalies, and see issues raised by client users across all organizations. By default they cannot retrain models, edit Layer 1 rules, or manage SIEM settings. The superadmin grants those capabilities individually. Every action taken under a granted permission is logged with a reference to the grant record.

**Client User** belongs to exactly one client organization and sees only that organization's data. The client ID is never submitted by the user , it is embedded in the JWT by the server at login time and enforced by both application logic and PostgreSQL Row-Level Security. No client user can influence, guess, or escalate their own `client_id` at any point in any request.

---

## Project Structure

```
soc_platform/
├── backend/
│   ├── app/
│   │   ├── main.py                    FastAPI application entry point
│   │   ├── core/
│   │   │   ├── audit.py               Audit log decorator
│   │   │   ├── config.py              Settings (Pydantic)
│   │   │   ├── dependencies.py        Auth dependencies (require_client, require_analyst, etc.)
│   │   │   ├── middleware.py          AuditMiddleware , every write
│   │   │   └── security.py            JWT, password hashing, Fernet helpers
│   │   ├── db/
│   │   │   ├── session.py             Async SQLAlchemy session
│   │   │   └── init_db.py             DB initialization
│   │   ├── models/                    SQLAlchemy async ORM models
│   │   ├── schemas/                   Pydantic v2 request/response models
│   │   ├── routers/
│   │   │   ├── admin.py               Superadmin endpoints
│   │   │   ├── analyst.py             Analyst endpoints
│   │   │   ├── auth.py                Auth (login, MFA, password reset, refresh)
│   │   │   ├── client.py              Client portal endpoints
│   │   │   ├── graylog.py             Graylog management endpoints
│   │   │   ├── payments.py            M-Pesa Daraja / subscription endpoints
│   │   │   ├── retrain.py             Model retrain and rollback endpoints
│   │   │   ├── rules.py               Layer 1 rule management
│   │   │   └── bootstrap_train.py     Initial model seeding endpoint
│   │   ├── siem/
│   │   │   ├── base.py                SIEMAdapter abstract base class
│   │   │   ├── factory.py             Adapter factory (reads siem_type)
│   │   │   ├── graylog.py             GraylogAdapter , Lucene queries ✅
│   │   │   └── stubs.py               WazuhAdapter, SplunkAdapter, ElasticAdapter,
│   │   │                              SentinelAdapter , all stubs 🔧
│   │   ├── services/
│   │   │   └── daraja.py              M-Pesa STK Push
│   │   └── utils/
│   │       └── excel_formatter.py     Shared Excel export (openpyxl)
│   ├── schedulers/
│   │   ├── log_collector.py           Every 3 min , fetch, normalize, upsert
│   │   ├── anomaly_engine.py          Every 5 min , L1 rules + L2 IF + IOC match
│   │   └── threat_intel.py            Every 6 hr , NVD, OTX, RSS, MITRE
│   └── alembic/                       Alembic migrations
│       └── versions/
└── frontend/
    ├── src/
    │   ├── pages/client/              Client portal pages
    │   ├── pages/analyst/             Analyst portal pages
    │   └── pages/admin/               Admin portal pages
    └── vite.config.js
```

**Frontend stack:** React 19, React Router v7, Zustand (state management), Axios, qrcode.react (MFA QR codes), Vite 8. There is no charting library declared as a dependency , charts are rendered with native DOM or inline approaches.

---

## Prerequisites

- Python 3.11 or later
- Node.js 18 or later
- PostgreSQL 15 or later
- A running Graylog instance (for current SIEM integration; others in progress)
- API keys for NVD, AlienVault OTX, Anthropic, and optionally Safaricom Daraja

---

## Environment Variables

Copy `.env.example` to `.env` and fill in every value before starting.

```env
# Database
DATABASE_URL=postgresql+asyncpg://soc_user:password@localhost/soc_platform

# Security
JWT_SECRET=<32+ random bytes , generate with: openssl rand -hex 32>
FERNET_KEY=<generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">

# Threat Intelligence
NVD_API_KEY=         # nvd.nist.gov/developers/request-an-api-key
OTX_API_KEY=         # otx.alienvault.com

# AI Summarization (threat intel feed)
CLAUDE_API_KEY=      # console.anthropic.com

# Payments , M-Pesa Daraja (Phase 4, build last)
DARAJA_CONSUMER_KEY=
DARAJA_CONSUMER_SECRET=
DARAJA_SHORTCODE=
DARAJA_PASSKEY=
DARAJA_CALLBACK_URL=

# Application
FRONTEND_ORIGIN=http://localhost:5173
ENVIRONMENT=development          # set to "production" to disable API docs and stack traces
MODEL_BASE_PATH=/opt/soc_platform/models

# Email (password reset)
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=
```

SIEM credentials (base URLs, API tokens, usernames, passwords) are stored per-client in the `clients` table, Fernet-encrypted before insert. They are never written to `.env` , the `.env` holds only the Fernet encryption key.

---

## Database Setup

```bash
# Create the database and user
psql -U postgres <<EOF
CREATE DATABASE soc_platform;
CREATE USER soc_user WITH PASSWORD 'your_strong_password';
GRANT ALL PRIVILEGES ON DATABASE soc_platform TO soc_user;
EOF

# Install Python dependencies
pip install -r backend/requirements.txt

# Run migrations , run this after every session that adds schema changes
cd backend
alembic upgrade head

# Create model storage directory
mkdir -p /opt/soc_platform/models
```

Row-Level Security policies are applied by migrations. The `app.current_client_id` and `app.current_role` session variables are set by the FastAPI dependency layer on every client-facing database connection , you do not configure this manually.

---

## Running the Backend

```bash
cd backend
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

In production, run behind Gunicorn with Uvicorn workers:

```bash
gunicorn app.main:app -k uvicorn.workers.UvicornWorker \
  --workers 4 --bind 0.0.0.0:8000
```

The OpenAPI docs are available at `http://localhost:8000/docs` in development. Setting `ENVIRONMENT=production` in `.env` disables both the docs and full stack traces in error responses.

---

## Running the Frontend

```bash
cd frontend
npm install
npm run dev
```

For a production build:

```bash
npm run build
# Serve the dist/ directory from nginx or any static file host
```

JWT access tokens are held in memory only , never written to `localStorage` or `sessionStorage`. The refresh token lives in an httpOnly cookie that JavaScript cannot read. An Axios interceptor handles silent token refresh transparently.

> **Insert screenshot here:** The client portal events page , named query tabs with notification badges, grouped event table showing first/middle/last timestamps, confirm and raise issue buttons, period filter.

---

## Running the Scheduler Processes

Each scheduler is a standalone Python script. In development, run them directly in separate terminals:

```bash
# Terminal 1 , log collection (every 3 minutes)
python backend/schedulers/log_collector.py

# Terminal 2 , anomaly engine (every 5 minutes, offset 1 minute from collector)
python backend/schedulers/anomaly_engine.py

# Terminal 3 , threat intelligence (every 6 hours)
python backend/schedulers/threat_intel.py
```

In production, manage them with systemd. Example unit for the log collector:

```ini
[Unit]
Description=SOC Log Collector
After=network.target postgresql.service

[Service]
User=soc
WorkingDirectory=/opt/soc_platform
ExecStart=/opt/soc_platform/venv/bin/python backend/schedulers/log_collector.py
Restart=always
RestartSec=10
EnvironmentFile=/opt/soc_platform/.env

[Install]
WantedBy=multi-user.target
```

Create an equivalent unit for `anomaly_engine.py` and `threat_intel.py`. The `scheduler_status` table records the last run time, status, duration, and event/anomaly counts for each process , visible as a live health panel in the analyst dashboard.

---

## ML Models

Models live under `MODEL_BASE_PATH`, organized by client integer ID and category:

```
/opt/soc_platform/models/
└── {client_id}/
    ├── AuthenticationEvents.pkl
    ├── AuthenticationEvents.bak.pkl
    ├── AccountManagementEvents.pkl
    ├── AccountManagementEvents.bak.pkl
    ├── ProcessCreationEvents.pkl
    └── ProcessCreationEvents.bak.pkl
```

The folder for a new client is created automatically during onboarding. An initial model must be trained before Layer 2 scoring runs for that client , Layer 1 rules and IOC matching still run in the meantime. A bootstrap training endpoint (`/admin/bootstrap-train`) handles this initial seeding.

The `ml_models` table records the full path, training timestamp, the analyst who triggered the retrain, training row count, feature column list, and any event IDs excluded from the last training run. Before overwriting a `.pkl` on retrain, the current model is copied to `.bak.pkl`. Rollback restores the `.bak.pkl` and updates `ml_models` accordingly. Both retrain and rollback are written to the audit log.

---

## Deployment Considerations

**Security**

Use HTTPS exclusively in production , Let's Encrypt certificates are free and auto-renewed via Certbot. Passwords are hashed with bcrypt at cost 12. SIEM credentials are Fernet-encrypted before storage. Password reset tokens are single-use, expire in 30 minutes, and are stored hashed in the database. All analyst and superadmin accounts require TOTP MFA. Accounts lock after 5 failed login attempts for 15 minutes. Destructive Graylog management actions require a re-authentication confirmation token with a 60-second validity window. Rate limiting on authentication endpoints is handled by `slowapi`.

**Client Isolation**

PostgreSQL Row-Level Security enforces client isolation at the database level. Application-level enforcement in FastAPI dependencies adds a second independent layer. No route that serves client data accepts `client_id` as user input , it always comes from the JWT, which is signed and tamper-proof.

**Scaling**

The FastAPI backend is stateless , all state lives in PostgreSQL , and can be horizontally scaled behind a load balancer. The three scheduler processes can run on a dedicated worker host; they only need network access to PostgreSQL and to the SIEM APIs.

With 15 clients generating events every three minutes across multiple query categories, `operational_events` will grow quickly. Partition it by `timestamp` using monthly partitions once you approach 10M+ rows. The existing indexes on `(client_id, timestamp DESC)` and the RLS policies are compatible with partitioned tables.

**Monitoring**

The `scheduler_status` table is the primary health signal. Alert if `last_run_at` for any process is more than 10 minutes old. Aggregate logs from all three scheduler processes to a central system (Loki, CloudWatch, or your own Graylog instance) for full observability.

**Backups**

Back up both the PostgreSQL database and `MODEL_BASE_PATH`. Model files are not large but retraining from scratch requires historical event data that may have aged out of the collection window. The `.bak.pkl` files provide one generation of local rollback.

---

## Contributing

Work through the build order in the architecture document , auth middleware, RLS policies, and the audit log decorator are dependencies for almost everything else and should be solid before building on top of them.

Before opening a pull request:

1. Run `alembic upgrade head` and confirm no migration conflicts.
2. Every new route must have the appropriate role dependency applied (`require_client`, `require_analyst`, `require_superadmin`), defined in `app/core/dependencies.py`.
3. Every client-data query must include an explicit `WHERE client_id = current_user.client_id` in addition to RLS. This two-layer enforcement is intentional and both layers must be present.
4. Every action that modifies data must write to `audit_log`. No route that changes state is mergeable without an audit log entry.
5. Flag any potential security vulnerability in the PR description, even if you believe it is low risk.

New SIEM adapters must implement all methods on `SIEMAdapter`. Methods not yet implemented must raise `NotImplementedError` with the adapter name in the message , never return empty data silently, as that would cause data gaps that look identical to a quiet network.

New event sources should be accompanied by normalization logic that ensures: timestamps are converted to EAT before storage, adapter-internal metadata fields are stripped, and the canonical field names expected by `add_time_features()` and `apply_freq_map()` are present in the output. The typed tables are the contract , normalization must satisfy it.

---

## License

This project is proprietary software. All rights reserved. Unauthorized copying, distribution, or modification is prohibited without explicit written permission from the project owner.

---

*Platform version: migration in progress , Streamlit → FastAPI + React 19. Built for production MSSP operations in East Africa.*
