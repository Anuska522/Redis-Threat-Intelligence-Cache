from fastapi import APIRouter, HTTPException, Query, status
from app.models.api_models import IndicatorCheckRequest
from app.models.threat import LookupResponse
from app.services.lookup_service import lookup_service

router = APIRouter(prefix="/api", tags=["Threat Intelligence Lookup"])


@router.get("/check", response_model=LookupResponse, summary="Perform cache-first threat lookup (GET)")
async def check_indicator_get(indicator: str = Query(..., min_length=1, max_length=2048, description="Indicator (IP, domain, or URL)")):
    try:
        return await lookup_service.lookup(indicator, force_refresh=False)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Lookup failed: {str(ex)}")


@router.post("/check", response_model=LookupResponse, summary="Perform cache-first threat lookup (POST)")
async def check_indicator_post(request: IndicatorCheckRequest):
    try:
        return await lookup_service.lookup(request.indicator, force_refresh=False)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Lookup failed: {str(ex)}")


@router.post("/refresh/{indicator:path}", response_model=LookupResponse, summary="Force refresh threat intelligence from source")
async def refresh_indicator(indicator: str):
    try:
        return await lookup_service.lookup(indicator, force_refresh=True)
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Refresh failed: {str(ex)}")
