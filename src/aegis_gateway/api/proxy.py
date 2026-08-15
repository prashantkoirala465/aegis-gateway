from fastapi import APIRouter, Depends

from aegis_gateway.middleware.auth import get_current_tenant
from aegis_gateway.schemas.auth import TenantContext

router = APIRouter(prefix="/v1", tags=["proxy"])


@router.get("/ping")
async def ping(tenant: TenantContext = Depends(get_current_tenant)) -> dict[str, str]:
    """Auth smoke-test endpoint for the Week-1 milestone. The real OpenAI-compatible
    proxy surface (/v1/chat/completions etc.) lands in Phase 2 behind this same
    get_current_tenant dependency."""
    return {"status": "ok", "tenant": tenant.tenant_name, "api_key_id": tenant.api_key_id}
