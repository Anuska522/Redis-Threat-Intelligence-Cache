from fastapi import APIRouter, Depends, HTTPException, status
from app.config import settings
from app.api.auth import verify_admin_key
from app.models.api_models import SettingsUpdateRequest
from app.services.redis_service import redis_service
from app.services.lookup_service import lookup_service

router = APIRouter(prefix="/api", tags=["Settings and Health"])


@router.get("/health", summary="Check health of application, Redis, and CTI provider")
async def health_check():
    await redis_service.connect()
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "redis": {
            "connected": redis_service.is_connected,
            "mode": redis_service.mode,
            "url": settings.REDIS_URL.split("@")[-1]  # Mask credentials if any
        },
        "cti_provider": {
            "active": lookup_service.active_provider_name,
            "virustotal_configured": bool(settings.VIRUSTOTAL_API_KEY)
        }
    }


@router.get("/settings", summary="Retrieve active runtime configuration (sanitized)")
async def get_settings():
    return {
        "ttl_malicious_seconds": settings.TTL_MALICIOUS_SECONDS,
        "ttl_benign_seconds": settings.TTL_BENIGN_SECONDS,
        "ttl_unknown_seconds": settings.TTL_UNKNOWN_SECONDS,
        "alert_risk_threshold": settings.ALERT_RISK_THRESHOLD,
        "cti_provider": lookup_service.active_provider_name,
        "virustotal_configured": bool(settings.VIRUSTOTAL_API_KEY),
        "redis_mode": redis_service.mode
    }


@router.post("/settings", summary="Update runtime settings (Administrative protected)")
async def update_settings(request: SettingsUpdateRequest, admin_key: str = Depends(verify_admin_key)):
    if request.ttl_malicious_seconds is not None:
        settings.TTL_MALICIOUS_SECONDS = request.ttl_malicious_seconds
    if request.ttl_benign_seconds is not None:
        settings.TTL_BENIGN_SECONDS = request.ttl_benign_seconds
    if request.ttl_unknown_seconds is not None:
        settings.TTL_UNKNOWN_SECONDS = request.ttl_unknown_seconds
    if request.alert_risk_threshold is not None:
        settings.ALERT_RISK_THRESHOLD = request.alert_risk_threshold
    if request.cti_provider is not None:
        lookup_service.set_active_provider(request.cti_provider)

    return {
        "status": "success",
        "message": "Configuration updated successfully",
        "settings": {
            "ttl_malicious_seconds": settings.TTL_MALICIOUS_SECONDS,
            "ttl_benign_seconds": settings.TTL_BENIGN_SECONDS,
            "ttl_unknown_seconds": settings.TTL_UNKNOWN_SECONDS,
            "alert_risk_threshold": settings.ALERT_RISK_THRESHOLD,
            "cti_provider": lookup_service.active_provider_name
        }
    }
