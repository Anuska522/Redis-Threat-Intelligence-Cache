from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from app.models.indicator import IndicatorType
from app.models.threat import VerdictEnum, AlertEvent


class IndicatorCheckRequest(BaseModel):
    indicator: str = Field(..., min_length=1, max_length=2048, description="IP, domain, or full URL to inspect")


class BlacklistAddRequest(BaseModel):
    indicator: str = Field(..., min_length=1, max_length=2048)
    reason: str = Field(default="Administrative manual blacklist entry", max_length=256)
    source: str = Field(default="admin_manual", max_length=64)


class BlacklistEntry(BaseModel):
    indicator: str
    indicator_type: IndicatorType
    reason: str
    source: str
    added_at: str
    added_by: str = "administrator"


class StatsResponse(BaseModel):
    total_lookups: int
    cache_hits: int
    cache_misses: int
    cache_hit_rate_pct: float
    cache_miss_rate_pct: float
    provider_requests: int
    provider_errors: int
    threats_detected: int
    avoided_requests: int
    blacklist_count: int
    avg_latency_ms: float
    avg_hit_latency_ms: float
    avg_miss_latency_ms: float
    active_provider: str
    redis_connected: bool
    redis_mode: str


class TopThreatItem(BaseModel):
    indicator: str
    score: float
    count: int
    indicator_type: Optional[str] = None
    verdict: Optional[str] = None


class SettingsUpdateRequest(BaseModel):
    ttl_malicious_seconds: Optional[int] = Field(None, ge=30, le=604800)
    ttl_benign_seconds: Optional[int] = Field(None, ge=30, le=604800)
    ttl_unknown_seconds: Optional[int] = Field(None, ge=10, le=86400)
    alert_risk_threshold: Optional[int] = Field(None, ge=1, le=100)
    cti_provider: Optional[str] = Field(None, pattern="^(demo|virustotal)$")


class BenchmarkRunRequest(BaseModel):
    sample_size: int = Field(default=20, ge=5, le=200)
    include_direct: bool = Field(default=True)
