from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from datetime import datetime, timezone
import time

from app.api.auth import verify_admin_key
from app.models.api_models import BlacklistAddRequest, BlacklistEntry
from app.models.threat import AlertEvent
from app.services.normalizer import normalizer
from app.services.redis_service import redis_service

router = APIRouter(prefix="/api/blacklist", tags=["Blacklist Management"])


@router.get("", response_model=List[BlacklistEntry], summary="Retrieve all blacklisted indicators")
async def list_blacklist():
    return await redis_service.get_all_blacklist()


@router.post("", response_model=BlacklistEntry, status_code=status.HTTP_201_CREATED, summary="Add indicator to administrative blacklist")
async def add_blacklist(request: BlacklistAddRequest, admin_key: str = Depends(verify_admin_key)):
    try:
        norm = normalizer.normalize(request.indicator)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))

    await redis_service.add_to_blacklist(
        indicator_type=norm.indicator_type,
        indicator=norm.normalized,
        reason=request.reason,
        source=request.source,
        added_by="administrator"
    )

    # Publish real-time event on Redis Pub/Sub
    now_iso = datetime.now(timezone.utc).isoformat()
    alert = AlertEvent(
        event_id=f"alt_bl_{int(time.time() * 1000)}",
        timestamp=now_iso,
        indicator=norm.normalized,
        indicator_type=norm.indicator_type,
        threat_score=100,
        severity="CRITICAL",
        categories=["administrative_blacklist"],
        source="administrative_portal",
        reason=f"Added to administrative blacklist: {request.reason}"
    )
    await redis_service.publish_alert(alert)

    return BlacklistEntry(
        indicator=norm.normalized,
        indicator_type=norm.indicator_type,
        reason=request.reason,
        source=request.source,
        added_at=now_iso,
        added_by="administrator"
    )


@router.delete("/{indicator:path}", summary="Remove indicator from administrative blacklist")
async def remove_blacklist(indicator: str, admin_key: str = Depends(verify_admin_key)):
    try:
        norm = normalizer.normalize(indicator)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))

    removed = await redis_service.remove_from_blacklist(norm.indicator_type, norm.normalized)
    if not removed:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Indicator '{norm.normalized}' not found on blacklist.")

    return {
        "status": "success",
        "message": f"Indicator '{norm.normalized}' removed from administrative blacklist.",
        "indicator": norm.normalized
    }
