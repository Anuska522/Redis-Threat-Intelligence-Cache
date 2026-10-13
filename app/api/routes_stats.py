from fastapi import APIRouter, Query
from typing import List, Dict, Any
from app.models.api_models import StatsResponse, TopThreatItem
from app.services.redis_service import redis_service
from app.services.lookup_service import lookup_service

router = APIRouter(prefix="/api", tags=["Operational Statistics"])


@router.get("/stats", response_model=StatsResponse, summary="Retrieve real-time cache and lookup metrics")
async def get_stats():
    data = await redis_service.get_stats(active_provider=lookup_service.active_provider_name)
    return StatsResponse(**data)


@router.get("/top-threats", response_model=List[TopThreatItem], summary="Get ranked top threats from Redis Sorted Set")
async def get_top_threats(limit: int = Query(10, ge=1, le=100)):
    return await redis_service.get_top_threats(limit=limit)


@router.get("/history", response_model=List[Dict[str, Any]], summary="Get recent lookup audit trail")
async def get_history(limit: int = Query(50, ge=1, le=100)):
    return await redis_service.get_lookup_history(limit=limit)
