import json
import logging
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Tuple
import redis.asyncio as aioredis
from fakeredis.aioredis import FakeRedis

from app.config import settings
from app.models.indicator import IndicatorType
from app.models.threat import ThreatRecord, VerdictEnum, AlertEvent
from app.models.api_models import BlacklistEntry, TopThreatItem

logger = logging.getLogger("redis_service")


class RedisService:
    def __init__(self):
        self._client: Optional[aioredis.Redis] = None
        self._is_fake: bool = False
        self._is_connected: bool = False
        self._pubsub = None
        self._lock = asyncio.Lock()

    async def connect(self) -> None:
        async with self._lock:
            if self._client is not None and self._is_connected:
                return

            try:
                # Attempt connection to real Redis server
                client = aioredis.from_url(
                    settings.REDIS_URL,
                    decode_responses=True,
                    socket_connect_timeout=settings.REDIS_TIMEOUT_SECONDS,
                    socket_timeout=settings.REDIS_TIMEOUT_SECONDS,
                    max_connections=settings.REDIS_MAX_CONNECTIONS
                )
                # Test ping
                await client.ping()
                self._client = client
                self._is_fake = False
                self._is_connected = True
                logger.info(f"Connected to standalone Redis server at {settings.REDIS_URL}")
            except Exception as ex:
                logger.warning(
                    f"Unable to connect to Redis server at {settings.REDIS_URL}: {ex}. "
                    "Falling back to embedded in-memory Redis engine (fakeredis)."
                )
                self._client = FakeRedis(decode_responses=True)
                self._is_fake = True
                self._is_connected = True
                logger.info("Embedded in-memory Redis engine initialized successfully.")

    async def disconnect(self) -> None:
        if self._client is not None:
            try:
                await self._client.aclose()
            except Exception:
                pass
            self._client = None
            self._is_connected = False

    @property
    def is_connected(self) -> bool:
        return self._is_connected

    @property
    def mode(self) -> str:
        return "in_memory_simulation" if self._is_fake else "redis_server"

    # -------------------------------------------------------------
    # 1. HASHES: Threat Records
    # -------------------------------------------------------------
    async def get_threat_record(self, redis_key: str) -> Optional[Tuple[ThreatRecord, int]]:
        await self.connect()
        data = await self._client.hgetall(redis_key)
        if not data:
            return None

        ttl = await self._client.ttl(redis_key)
        if ttl == -2:
            # Key does not exist / expired
            return None

        try:
            categories_raw = data.get("categories", "[]")
            categories = json.loads(categories_raw) if categories_raw else []

            record = ThreatRecord(
                indicator=data.get("indicator", ""),
                original_indicator=data.get("original_indicator") or data.get("indicator", ""),
                indicator_type=IndicatorType(data.get("indicator_type", "domain")),
                verdict=VerdictEnum(data.get("verdict", "unknown")),
                malicious=(data.get("malicious", "false").lower() == "true"),
                threat_score=int(data.get("threat_score", "0")),
                confidence=float(data.get("confidence", "0.0")),
                categories=categories,
                source=data.get("source", "redis_cache"),
                first_seen=data.get("first_seen") or None,
                last_seen=data.get("last_seen") or None,
                checked_at=data.get("checked_at", datetime.now(timezone.utc).isoformat()),
                ttl_seconds=int(data.get("ttl_seconds", str(ttl if ttl > 0 else 3600))),
                description=data.get("description") or None
            )
            return record, max(0, ttl)
        except Exception as e:
            logger.error(f"Error deserializing threat record for key {redis_key}: {e}")
            return None

    async def store_threat_record(self, redis_key: str, record: ThreatRecord, ttl_seconds: int) -> None:
        await self.connect()
        mapping = {
            "indicator": record.indicator,
            "original_indicator": record.original_indicator or record.indicator,
            "indicator_type": record.indicator_type.value,
            "verdict": record.verdict.value,
            "malicious": "true" if record.malicious else "false",
            "threat_score": str(record.threat_score),
            "confidence": str(record.confidence),
            "categories": json.dumps(record.categories),
            "source": record.source,
            "first_seen": record.first_seen or "",
            "last_seen": record.last_seen or "",
            "checked_at": record.checked_at,
            "ttl_seconds": str(ttl_seconds),
            "description": record.description or ""
        }
        await self._client.hset(redis_key, mapping=mapping)
        if ttl_seconds > 0:
            await self._client.expire(redis_key, ttl_seconds)

    # -------------------------------------------------------------
    # 2. SETS: Blacklists (IP, Domain, URL)
    # -------------------------------------------------------------
    def _blacklist_set_key(self, indicator_type: IndicatorType) -> str:
        return f"blacklist:{indicator_type.value}"

    async def is_blacklisted(self, indicator_type: IndicatorType, indicator: str) -> bool:
        await self.connect()
        set_key = self._blacklist_set_key(indicator_type)
        return bool(await self._client.sismember(set_key, indicator))

    async def add_to_blacklist(
        self,
        indicator_type: IndicatorType,
        indicator: str,
        reason: str = "Administrative manual blacklist entry",
        source: str = "admin_manual",
        added_by: str = "administrator"
    ) -> None:
        await self.connect()
        set_key = self._blacklist_set_key(indicator_type)
        await self._client.sadd(set_key, indicator)

        meta_key = f"blacklist:meta:{indicator}"
        mapping = {
            "indicator": indicator,
            "indicator_type": indicator_type.value,
            "reason": reason,
            "source": source,
            "added_by": added_by,
            "added_at": datetime.now(timezone.utc).isoformat()
        }
        await self._client.hset(meta_key, mapping=mapping)

    async def remove_from_blacklist(self, indicator_type: IndicatorType, indicator: str) -> bool:
        await self.connect()
        set_key = self._blacklist_set_key(indicator_type)
        removed = await self._client.srem(set_key, indicator)
        await self._client.delete(f"blacklist:meta:{indicator}")
        return bool(removed)

    async def get_all_blacklist(self) -> List[BlacklistEntry]:
        await self.connect()
        entries = []
        for itype in [IndicatorType.IP, IndicatorType.DOMAIN, IndicatorType.URL]:
            set_key = self._blacklist_set_key(itype)
            members = await self._client.smembers(set_key)
            for member in members:
                meta = await self._client.hgetall(f"blacklist:meta:{member}")
                entries.append(BlacklistEntry(
                    indicator=member,
                    indicator_type=itype,
                    reason=meta.get("reason", "Administrative blacklist entry"),
                    source=meta.get("source", "admin_manual"),
                    added_at=meta.get("added_at", datetime.now(timezone.utc).isoformat()),
                    added_by=meta.get("added_by", "administrator")
                ))
        return entries

    async def get_blacklist_count(self) -> int:
        await self.connect()
        count = 0
        for itype in [IndicatorType.IP, IndicatorType.DOMAIN, IndicatorType.URL]:
            set_key = self._blacklist_set_key(itype)
            count += await self._client.scard(set_key)
        return count

    # -------------------------------------------------------------
    # 3. SORTED SETS: Threat Rankings (rank:threats)
    # -------------------------------------------------------------
    async def record_indicator_lookup_rank(self, indicator: str, delta: float = 1.0) -> None:
        await self.connect()
        await self._client.zincrby("rank:threats", delta, indicator)

    async def get_top_threats(self, limit: int = 10) -> List[TopThreatItem]:
        await self.connect()
        # Returns list of (indicator, score) sorted descending
        results = await self._client.zrevrange("rank:threats", 0, limit - 1, withscores=True)
        items = []
        for indicator, score in results:
            items.append(TopThreatItem(
                indicator=indicator,
                score=score,
                count=int(score)
            ))
        return items

    # -------------------------------------------------------------
    # 4. STRINGS / ATOMIC COUNTERS: Lookups & Stats
    # -------------------------------------------------------------
    async def incr_stat(self, metric: str, amount: int = 1) -> int:
        await self.connect()
        return await self._client.incrby(f"stats:lookups:{metric}", amount)

    async def record_latency(self, latency_ms: float, is_hit: bool) -> None:
        await self.connect()
        await self._client.incrbyfloat("stats:latency:total_ms", latency_ms)
        await self._client.incr("stats:latency:total_count")
        if is_hit:
            await self._client.incrbyfloat("stats:latency:hit_ms", latency_ms)
            await self._client.incr("stats:latency:hit_count")
        else:
            await self._client.incrbyfloat("stats:latency:miss_ms", latency_ms)
            await self._client.incr("stats:latency:miss_count")

    async def get_stats(self, active_provider: str) -> Dict[str, Any]:
        await self.connect()
        # Read atomic counters
        total_lookups = int(await self._client.get("stats:lookups:total") or 0)
        cache_hits = int(await self._client.get("stats:lookups:hits") or 0)
        cache_misses = int(await self._client.get("stats:lookups:misses") or 0)
        provider_requests = int(await self._client.get("stats:lookups:provider_requests") or 0)
        provider_errors = int(await self._client.get("stats:lookups:provider_errors") or 0)
        threats_detected = int(await self._client.get("stats:lookups:threats_detected") or 0)

        hit_rate = (cache_hits / total_lookups * 100.0) if total_lookups > 0 else 0.0
        miss_rate = (cache_misses / total_lookups * 100.0) if total_lookups > 0 else 0.0
        avoided_requests = cache_hits

        # Latencies
        total_lat_ms = float(await self._client.get("stats:latency:total_ms") or 0.0)
        total_lat_cnt = int(await self._client.get("stats:latency:total_count") or 0)
        avg_latency = (total_lat_ms / total_lat_cnt) if total_lat_cnt > 0 else 0.0

        hit_lat_ms = float(await self._client.get("stats:latency:hit_ms") or 0.0)
        hit_lat_cnt = int(await self._client.get("stats:latency:hit_count") or 0)
        avg_hit_latency = (hit_lat_ms / hit_lat_cnt) if hit_lat_cnt > 0 else 0.0

        miss_lat_ms = float(await self._client.get("stats:latency:miss_ms") or 0.0)
        miss_lat_cnt = int(await self._client.get("stats:latency:miss_count") or 0)
        avg_miss_latency = (miss_lat_ms / miss_lat_cnt) if miss_lat_cnt > 0 else 0.0

        blacklist_count = await self.get_blacklist_count()

        return {
            "total_lookups": total_lookups,
            "cache_hits": cache_hits,
            "cache_misses": cache_misses,
            "cache_hit_rate_pct": round(hit_rate, 2),
            "cache_miss_rate_pct": round(miss_rate, 2),
            "provider_requests": provider_requests,
            "provider_errors": provider_errors,
            "threats_detected": threats_detected,
            "avoided_requests": avoided_requests,
            "blacklist_count": blacklist_count,
            "avg_latency_ms": round(avg_latency, 2),
            "avg_hit_latency_ms": round(avg_hit_latency, 2),
            "avg_miss_latency_ms": round(avg_miss_latency, 2),
            "active_provider": active_provider,
            "redis_connected": self._is_connected,
            "redis_mode": self.mode
        }

    # -------------------------------------------------------------
    # 5. PUB/SUB: Real-Time Alerts
    # -------------------------------------------------------------
    async def publish_alert(self, alert: AlertEvent) -> None:
        await self.connect()
        payload = alert.model_dump_json()
        await self._client.publish("alerts", payload)
        # Store in bounded alert history list (capped at 100)
        await self._client.lpush("history:alerts", payload)
        await self._client.ltrim("history:alerts", 0, 99)

    async def get_alert_history(self, limit: int = 50) -> List[AlertEvent]:
        await self.connect()
        raw_items = await self._client.lrange("history:alerts", 0, limit - 1)
        alerts = []
        for item in raw_items:
            try:
                data = json.loads(item)
                alerts.append(AlertEvent(**data))
            except Exception:
                pass
        return alerts

    # -------------------------------------------------------------
    # 6. HISTORY: Lookup Audit Trail (capped at 100)
    # -------------------------------------------------------------
    async def record_lookup_history(self, summary_json: str) -> None:
        await self.connect()
        await self._client.lpush("history:lookups", summary_json)
        await self._client.ltrim("history:lookups", 0, 99)

    async def get_lookup_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        await self.connect()
        raw_items = await self._client.lrange("history:lookups", 0, limit - 1)
        history = []
        for item in raw_items:
            try:
                history.append(json.loads(item))
            except Exception:
                pass
        return history

    # -------------------------------------------------------------
    # 7. PUB/SUB Subscriber
    # -------------------------------------------------------------
    def get_pubsub(self):
        return self._client.pubsub()


redis_service = RedisService()
