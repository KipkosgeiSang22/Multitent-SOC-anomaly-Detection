from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.audit_log import AuditLog
import json


async def log_action(
    db: AsyncSession,
    request: Request,
    event_type: str,
    user_id: int = None,
    client_id: int = None,
    target_id: int = None,
    details: dict = None,
    flush_only: bool = False,
):
    """
    Records security and operational events to the audit_log table.

    flush_only=False (default): commits immediately — used by auth routes
      where the audit entry is a self-contained transaction.
    flush_only=True: only flushes — used by admin/analyst routes where the
      audit entry must participate in the caller's transaction.
      The caller is responsible for the final db.commit().
    """
    try:
        audit_entry = AuditLog(
            user_id=user_id,
            event_type=event_type,
            client_id=client_id,
            target_id=target_id,
            details=details or {},
            ip_address=request.client.host if request.client else "127.0.0.1",
            user_agent=request.headers.get("user-agent", "unknown")
        )
        db.add(audit_entry)
        if flush_only:
            await db.flush()
        else:
            await db.commit()
    except Exception as e:
        print(f"CRITICAL: Audit Log failed: {e}")
        if not flush_only:
            await db.rollback()
