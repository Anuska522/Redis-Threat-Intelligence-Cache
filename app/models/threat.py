from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field
from app.models.indicator import IndicatorType


class VerdictEnum(str, Enum):
    MALICIOUS = "malicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"


class ThreatRecord(BaseModel):
    indicator: str
    original_indicator: Optional[str] = None
    indicator_type: IndicatorType
    verdict: VerdictEnum = VerdictEnum.UNKNOWN
    malicious: bool = False
    threat_score: int = Field(default=0, ge=0, le=100)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    categories: List[str] = Field(default_factory=list)
    source: str = "unknown"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    checked_at: str
    ttl_seconds: int = 3600
    description: Optional[str] = None


class LookupResponse(BaseModel):
    indicator: str
    original_indicator: str
    indicator_type: IndicatorType
    verdict: VerdictEnum
    malicious: bool
    threat_score: int
    confidence: float
    categories: List[str]
    source: str
    cache_status: str  # "hit" or "miss"
    latency_ms: float
    ttl_remaining: Optional[int] = None
    ttl_policy: int
    checked_at: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    description: Optional[str] = None
    is_blacklisted: bool = False
    redis_key: str
    alert_triggered: bool = False


class AlertEvent(BaseModel):
    event_id: str
    timestamp: str
    indicator: str
    indicator_type: IndicatorType
    threat_score: int
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    categories: List[str]
    source: str
    reason: str
