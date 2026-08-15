import uuid
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from aegis_gateway.db.models import AuditLog
from aegis_gateway.db.session import set_rls_context


async def write_audit_event(
    session: AsyncSession,
    *,
    tenant_id: uuid.UUID | None,
    event_type: str,
    correlation_id: str | None,
    detail: dict[str, Any],
) -> None:
    """Synchronous, same-request write — never queued through arq. A background job
    can be delayed or lost on a crash before it runs; for security-critical events
    (auth failures, PII redactions, injection blocks, admin actions) that gap is
    unacceptable, so this commits immediately in the calling request.

    Always writes with RLS bypassed rather than whatever tenant context the caller's
    session currently has set: audit logging is a system-level operation, not a
    tenant-scoped user query, and the event's tenant_id (or None, for pre-auth
    failures where the tenant isn't known yet) is what actually matters — not
    whichever tenant context happened to be active when this was called.

    `detail` must never contain raw prompt/PII content — only categories, counts,
    scores, and other metadata. Callers are responsible for that; this function does
    not (and cannot) redact its input.
    """
    await set_rls_context(session, tenant_id=None, bypass=True)
    session.add(
        AuditLog(
            tenant_id=tenant_id,
            event_type=event_type,
            correlation_id=correlation_id,
            detail=detail,
        )
    )
    await session.commit()
