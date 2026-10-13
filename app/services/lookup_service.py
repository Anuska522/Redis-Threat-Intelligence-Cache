import time
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Tuple

from app.config import settings
from app.models.indicator import IndicatorType, NormalizationResult
from app.models.threat import ThreatRecord, LookupResponse, VerdictEnum, AlertEvent
from app.services.normalizer import normalizer
from app.services.redis_service import redis_service
from app.providers.demo_provider import LocalDemoProvider
from app.providers.virustotal import VirusTotalProvider

logger = logging.getLogger("lookup_service")


class ThreatLookupService:
    def __init__(self):
        self._demo_provider = LocalDemoProvider()
        self._vt_provider = VirusTotalProvider()
        self._active_provider_name = settings.CTI_PROVIDER

    @property
    def active_provider_name(self) -> str:
        return self._active_provider_name

    def set_active_provider(self, provider_name: str) -> None:
        if provider_name in ("demo", "virustotal"):
            self._active_provider_name = provider_name
            settings.CTI_PROVIDER = provider_name
            logger.info(f"Active threat intelligence provider switched to {provider_name}")
        else:
            raise ValueError(f"Invalid provider: {provider_name}. Expected 'demo' or 'virustotal'")

    def _get_provider(self):
        if self._active_provider_name == "virustotal":
            return self._vt_provider
        return self._demo_provider

    async def lookup(self, raw_indicator: str, force_refresh: bool = False) -> LookupResponse:
        start_time = time.perf_counter()

        # Step 1-3: Validate & Normalize
        norm: NormalizationResult = normalizer.normalize(raw_indicator)
        now_iso = datetime.now(timezone.utc).isoformat()

        # Step 4: Check Blacklist (Administrative Set membership)
        is_bl = await redis_service.is_blacklisted(norm.indicator_type, norm.normalized)
        if is_bl:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            await redis_service.incr_stat("total")
            await redis_service.incr_stat("hits")
            await redis_service.record_latency(latency_ms, is_hit=True)
            await redis_service.record_indicator_lookup_rank(norm.normalized, delta=1.0)

            resp = LookupResponse(
                indicator=norm.normalized,
                original_indicator=norm.original,
                indicator_type=norm.indicator_type,
                verdict=VerdictEnum.MALICIOUS,
                malicious=True,
                threat_score=100,
                confidence=1.0,
                categories=["administrative_blacklist"],
                source="administrative_blacklist",
                cache_status="hit",
                latency_ms=round(latency_ms, 2),
                ttl_remaining=None,
                ttl_policy=0,
                checked_at=now_iso,
                first_seen=now_iso,
                last_seen=now_iso,
                description="Indicator is explicitly flagged on the administrative blacklist",
                is_blacklisted=True,
                redis_key=norm.redis_key,
                alert_triggered=False
            )
            await redis_service.record_lookup_history(resp.model_dump_json())
            return resp

        # Step 5: Check Redis Cache (if not force_refresh)
        cached_result = None
        if not force_refresh:
            cached_result = await redis_service.get_threat_record(norm.redis_key)

        if cached_result is not None:
            # Cache Hit!
            record, ttl_remaining = cached_result
            latency_ms = (time.perf_counter() - start_time) * 1000.0

            await redis_service.incr_stat("total")
            await redis_service.incr_stat("hits")
            await redis_service.record_latency(latency_ms, is_hit=True)
            await redis_service.record_indicator_lookup_rank(norm.normalized, delta=1.0)

            resp = LookupResponse(
                indicator=record.indicator,
                original_indicator=norm.original,
                indicator_type=record.indicator_type,
                verdict=record.verdict,
                malicious=record.malicious,
                threat_score=record.threat_score,
                confidence=record.confidence,
                categories=record.categories,
                source="redis_cache",
                cache_status="hit",
                latency_ms=round(latency_ms, 2),
                ttl_remaining=ttl_remaining,
                ttl_policy=record.ttl_seconds,
                checked_at=now_iso,
                first_seen=record.first_seen,
                last_seen=record.last_seen,
                description=record.description,
                is_blacklisted=False,
                redis_key=norm.redis_key,
                alert_triggered=False
            )
            await redis_service.record_lookup_history(resp.model_dump_json())
            return resp

        # Step 6: Cache Miss -> Query Active Provider
        await redis_service.incr_stat("total")
        await redis_service.incr_stat("misses")
        await redis_service.incr_stat("provider_requests")

        provider = self._get_provider()
        try:
            record: ThreatRecord = await provider.lookup(
                norm.normalized,
                norm.indicator_type,
                norm.original
            )
        except Exception as e:
            await redis_service.incr_stat("provider_errors")
            logger.error(f"Provider lookup failed: {e}")
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return LookupResponse(
                indicator=norm.normalized,
                original_indicator=norm.original,
                indicator_type=norm.indicator_type,
                verdict=VerdictEnum.UNAVAILABLE,
                malicious=False,
                threat_score=0,
                confidence=0.0,
                categories=["provider_failure"],
                source=provider.name,
                cache_status="miss",
                latency_ms=round(latency_ms, 2),
                ttl_remaining=0,
                ttl_policy=0,
                checked_at=now_iso,
                first_seen=None,
                last_seen=None,
                description=f"External intelligence provider error: {str(e)}",
                is_blacklisted=False,
                redis_key=norm.redis_key,
                alert_triggered=False
            )

        # Determine appropriate TTL policy
        if record.verdict == VerdictEnum.MALICIOUS:
            ttl_policy = settings.TTL_MALICIOUS_SECONDS
        elif record.verdict == VerdictEnum.BENIGN:
            ttl_policy = settings.TTL_BENIGN_SECONDS
        elif record.verdict == VerdictEnum.UNKNOWN:
            ttl_policy = settings.TTL_UNKNOWN_SECONDS
        else:
            # Unavailable or errors: very short 60s cache
            ttl_policy = 60

        # Store in Redis Cache
        record.ttl_seconds = ttl_policy
        await redis_service.store_threat_record(norm.redis_key, record, ttl_policy)

        # Update stats & rankings
        await redis_service.record_indicator_lookup_rank(norm.normalized, delta=1.0)
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        await redis_service.record_latency(latency_ms, is_hit=False)

        # Check alert trigger condition
        alert_triggered = False
        if record.malicious or record.threat_score >= settings.ALERT_RISK_THRESHOLD:
            alert_triggered = True
            await redis_service.incr_stat("threats_detected")

            severity = "CRITICAL" if record.threat_score >= 90 else (
                "HIGH" if record.threat_score >= 70 else "MEDIUM"
            )

            alert_event = AlertEvent(
                event_id=f"alt_{int(time.time() * 1000)}",
                timestamp=now_iso,
                indicator=norm.normalized,
                indicator_type=norm.indicator_type,
                threat_score=record.threat_score,
                severity=severity,
                categories=record.categories,
                source=record.source,
                reason=f"High risk threat detected (Score: {record.threat_score}/100)"
            )
            await redis_service.publish_alert(alert_event)

        resp = LookupResponse(
            indicator=record.indicator,
            original_indicator=norm.original,
            indicator_type=record.indicator_type,
            verdict=record.verdict,
            malicious=record.malicious,
            threat_score=record.threat_score,
            confidence=record.confidence,
            categories=record.categories,
            source=record.source,
            cache_status="miss",
            latency_ms=round(latency_ms, 2),
            ttl_remaining=ttl_policy,
            ttl_policy=ttl_policy,
            checked_at=now_iso,
            first_seen=record.first_seen,
            last_seen=record.last_seen,
            description=record.description,
            is_blacklisted=False,
            redis_key=norm.redis_key,
            alert_triggered=alert_triggered
        )

        await redis_service.record_lookup_history(resp.model_dump_json())
        return resp


lookup_service = ThreatLookupService()
