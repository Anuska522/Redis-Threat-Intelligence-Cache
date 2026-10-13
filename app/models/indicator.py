from enum import Enum
from pydantic import BaseModel, Field
from typing import Optional


class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"


class NormalizationResult(BaseModel):
    original: str
    normalized: str
    indicator_type: IndicatorType
    redis_key: str
    lookup_hash: Optional[str] = None
    ip_version: Optional[int] = None
    port: Optional[int] = None
    canonical_url: Optional[str] = None
