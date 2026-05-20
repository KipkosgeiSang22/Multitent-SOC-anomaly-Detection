"""
Run once after alembic upgrade head to:
1. Apply RLS policies on all client-data tables
2. Seed the superadmin account
3. Seed default Layer 1 rules template
"""
import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from sqlalchemy import text
from app.db.session import AsyncSessionLocal
from app.core.config import settings
from passlib.context import CryptContext
from app.core.config import Settings

pwd_context = CryptContext(schemes=["bcrypt"], bcrypt__rounds=12)

RLS_STATEMENTS = """
-- Enable RLS on all client-data tables
ALTER TABLE operational_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE account_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE process_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE anomalies ENABLE ROW LEVEL SECURITY;
ALTER TABLE ml_models ENABLE ROW LEVEL SECURITY;
ALTER TABLE layer1_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE payments ENABLE ROW LEVEL SECURITY;

-- Drop existing policies if re-running
DROP POLICY IF EXISTS client_isolation ON operational_events;
DROP POLICY IF EXISTS client_isolation ON auth_events;
DROP POLICY IF EXISTS client_isolation ON account_events;
DROP POLICY IF EXISTS client_isolation ON process_events;
DROP POLICY IF EXISTS client_isolation ON anomalies;
DROP POLICY IF EXISTS client_isolation ON ml_models;
DROP POLICY IF EXISTS client_isolation ON layer1_rules;
DROP POLICY IF EXISTS client_isolation ON payments;

-- Create isolation policies
CREATE POLICY client_isolation ON operational_events
    USING (
        client_id = NULLIF(current_setting('app.current_client_id', true), '')::int
        OR current_setting('app.current_role', true) IN ('analyst', 'superadmin')
    );

CREATE POLICY client_isolation ON auth_events
    USING (
        client_id = NULLIF(current_setting('app.current_client_id', true), '')::int
        OR current_setting('app.current_role', true) IN ('analyst', 'superadmin')
    );

CREATE POLICY client_isolation ON account_events
    USING (
        client_id = NULLIF(current_setting('app.current_client_id', true), '')::int
        OR current_setting('app.current_role', true) IN ('analyst', 'superadmin')
    );

CREATE POLICY client_isolation ON process_events
    USING (
        client_id = NULLIF(current_setting('app.current_client_id', true), '')::int
        OR current_setting('app.current_role', true) IN ('analyst', 'superadmin')
    );

CREATE POLICY client_isolation ON anomalies
    USING (
        client_id = NULLIF(current_setting('app.current_client_id', true), '')::int
        OR current_setting('app.current_role', true) IN ('analyst', 'superadmin')
    );

CREATE POLICY client_isolation ON ml_models
    USING (
        client_id = NULLIF(current_setting('app.current_client_id', true), '')::int
        OR current_setting('app.current_role', true) IN ('analyst', 'superadmin')
    );

CREATE POLICY client_isolation ON layer1_rules
    USING (
        client_id = NULLIF(current_setting('app.current_client_id', true), '')::int
        OR current_setting('app.current_role', true) IN ('analyst', 'superadmin')
    );

CREATE POLICY client_isolation ON payments
    USING (
        client_id = NULLIF(current_setting('app.current_client_id', true), '')::int
        OR current_setting('app.current_role', true) IN ('analyst', 'superadmin')
    );

-- Grant soc_user permission to set session-level settings
ALTER ROLE soc_user SET search_path = public;
"""

DEFAULT_LAYER1_RULES = [
    {
        "rule_name": "Brute Force Detection",
        "description": "More than 5 failed logins within 5 minutes from same IP",
        "category": "AuthenticationEvents",
        "conditions": {
            "field": "EventID",
            "operator": "eq",
            "values": [4625],
            "aggregation": "count",
            "threshold": 5,
            "window_minutes": 5,
            "group_by": "IpAddress"
        },
        "severity": "high",
    },
    {
        "rule_name": "Privilege Escalation",
        "description": "Sensitive privilege assigned to non-admin account",
        "category": "AuthenticationEvents",
        "conditions": {
            "field": "EventID",
            "operator": "in",
            "values": [4672, 4728, 4732],
            "aggregation": "count",
            "threshold": 1,
            "window_minutes": 1,
            "group_by": "TargetUserName"
        },
        "severity": "critical",
    },
    {
        "rule_name": "Suspicious Process Execution",
        "description": "LOLBins, encoded PowerShell, or net user commands",
        "category": "ProcessCreationEvents",
        "conditions": {
            "field": "CommandLine",
            "operator": "contains_any",
            "values": [
                "powershell -enc", "powershell -e ",
                "net user /add", "psexec", "mimikatz",
                "whoami", "cmd.exe /c"
            ],
            "aggregation": "count",
            "threshold": 1,
            "window_minutes": 1,
            "group_by": "SubjectUserName"
        },
        "severity": "critical",
    },
    {
        "rule_name": "Off-Hours Activity",
        "description": "Activity outside 07:00-19:00 EAT",
        "category": "AuthenticationEvents",
        "conditions": {
            "field": "hour",
            "operator": "outside_range",
            "values": [7, 19],
            "aggregation": "count",
            "threshold": 1,
            "window_minutes": 1,
            "group_by": "TargetUserName"
        },
        "severity": "medium",
    },
    {
        "rule_name": "Account Creation Followed by Deletion",
        "description": "Account created and deleted in rapid succession",
        "category": "AccountManagementEvents",
        "conditions": {
            "field": "EventID",
            "operator": "in",
            "values": [4720, 4726],
            "aggregation": "count",
            "threshold": 2,
            "window_minutes": 10,
            "group_by": "TargetUserName"
        },
        "severity": "high",
    },
]


async def apply_rls(session):
    print("Applying RLS policies...")
    for statement in RLS_STATEMENTS.strip().split(";"):
        stmt = statement.strip()
        if stmt:
            await session.execute(text(stmt))
    await session.commit()
    print("RLS policies applied.")


async def seed_superadmin(session):
    if not settings.ADMIN_PASSWORD:
        print("Error: ADMIN PASSWORD not set in the environment. Aborting")
    result = await session.execute(
        text("SELECT id FROM users WHERE role = 'superadmin' LIMIT 1")
    )
    if result.fetchone():
        print("Superadmin already exists — skipping.")
        return

    hashed = pwd_context.hash(settings.ADMIN_PASSWORD)
    await session.execute(
        text("""
            INSERT INTO users
              (username, email, password_hash, role, is_active,
               force_password_change, mfa_enabled, failed_login_attempts)
            VALUES
              (:username, :email, :hash, 'superadmin', true, true, false, 0)
        """),
        {
            "username": settings.ADMIN_USERNAME,
            "email": "admin@socplatform.local",
            "hash": hashed,
        }
    )
    await session.commit()
    print(f"Superadmin seeded — username: {settings.ADMIN_USERNAME}")
    print("You will be forced to change this password on first login.")



async def seed_default_rules_for_client(session, client_id: int,
                                        created_by: int):
    for rule in DEFAULT_LAYER1_RULES:
        existing = await session.execute(
            text("""
                SELECT id FROM layer1_rules
                WHERE client_id = :cid AND rule_name = :name
            """),
            {"cid": client_id, "name": rule["rule_name"]}
        )
        if existing.fetchone():
            continue
        import json
        await session.execute(
            text("""
                INSERT INTO layer1_rules
                  (client_id, rule_name, description, category,
                   conditions, severity, enabled, created_by, updated_by)
                VALUES
                  (:client_id, :rule_name, :description, :category,
                   :conditions, :severity, true, :created_by, :created_by)
            """),
            {
                "client_id": client_id,
                "rule_name": rule["rule_name"],
                "description": rule["description"],
                "category": rule["category"],
                "conditions": json.dumps(rule["conditions"]),
                "severity": rule["severity"],
                "created_by": created_by,
            }
        )
    await session.commit()
    print(f"Default Layer 1 rules seeded for client_id={client_id}")


async def main():
    async with AsyncSessionLocal() as session:
        await apply_rls(session)
        await seed_superadmin(session)
    print("\nSession 1 complete. Run alembic upgrade head before this script.")
    print("To seed rules for a client, call seed_default_rules_for_client()")
    print("from the client creation endpoint.")


if __name__ == "__main__":
    asyncio.run(main())