import pytest
from app.services.redis_service import redis_service
from app.models.indicator import IndicatorType
from app.models.threat import ThreatRecord, VerdictEnum, AlertEvent


@pytest.mark.asyncio
async def test_redis_connection():
    await redis_service.connect()
    assert redis_service.is_connected is True
    assert redis_service.mode in ("in_memory_simulation", "redis_server")


@pytest.mark.asyncio
async def test_threat_record_hash_storage_and_ttl():
    await redis_service.connect()
    key = "ti:ip:192.0.2.1"
    record = ThreatRecord(
        indicator="192.0.2.1",
        indicator_type=IndicatorType.IP,
        verdict=VerdictEnum.MALICIOUS,
        malicious=True,
        threat_score=85,
        confidence=0.9,
        categories=["botnet"],
        source="test_source",
        checked_at="2026-08-22T10:00:00Z",
        ttl_seconds=300
    )

    await redis_service.store_threat_record(key, record, ttl_seconds=300)
    result = await redis_service.get_threat_record(key)
    assert result is not None
    loaded_record, ttl_remaining = result
    assert loaded_record.indicator == "192.0.2.1"
    assert loaded_record.verdict == VerdictEnum.MALICIOUS
    assert loaded_record.malicious is True
    assert loaded_record.threat_score == 85
    assert loaded_record.categories == ["botnet"]
    assert ttl_remaining > 0


@pytest.mark.asyncio
async def test_blacklist_set_operations():
    await redis_service.connect()
    test_ip = "198.51.100.99"

    # Add to blacklist set
    await redis_service.add_to_blacklist(
        indicator_type=IndicatorType.IP,
        indicator=test_ip,
        reason="Test manual block",
        source="unit_test"
    )

    # Check membership
    is_member = await redis_service.is_blacklisted(IndicatorType.IP, test_ip)
    assert is_member is True

    # List all
    entries = await redis_service.get_all_blacklist()
    found = any(e.indicator == test_ip for e in entries)
    assert found is True

    # Remove
    removed = await redis_service.remove_from_blacklist(IndicatorType.IP, test_ip)
    assert removed is True
    assert await redis_service.is_blacklisted(IndicatorType.IP, test_ip) is False


@pytest.mark.asyncio
async def test_sorted_set_top_threats():
    await redis_service.connect()
    ind_a = "indicator-alpha.com"
    ind_b = "indicator-beta.com"

    await redis_service.record_indicator_lookup_rank(ind_a, 5.0)
    await redis_service.record_indicator_lookup_rank(ind_b, 10.0)

    top = await redis_service.get_top_threats(limit=5)
    indicators = [t.indicator for t in top]
    assert ind_b in indicators
    # ind_b should rank higher or equal to ind_a
    score_b = next(t.score for t in top if t.indicator == ind_b)
    score_a = next(t.score for t in top if t.indicator == ind_a)
    assert score_b >= score_a


@pytest.mark.asyncio
async def test_atomic_counters_and_stats():
    await redis_service.connect()
    total_before = (await redis_service.get_stats("demo"))["total_lookups"]
    await redis_service.incr_stat("total", 1)
    await redis_service.incr_stat("hits", 1)
    await redis_service.record_latency(1.5, is_hit=True)

    stats = await redis_service.get_stats("demo")
    assert stats["total_lookups"] == total_before + 1
    assert stats["cache_hits"] >= 1
    assert stats["avg_hit_latency_ms"] >= 0.0


@pytest.mark.asyncio
async def test_pubsub_alert_publication():
    await redis_service.connect()
    alert = AlertEvent(
        event_id="test_alert_1",
        timestamp="2026-08-22T12:00:00Z",
        indicator="198.51.100.22",
        indicator_type=IndicatorType.IP,
        threat_score=95,
        severity="CRITICAL",
        categories=["c2"],
        source="test",
        reason="Unit test alert"
    )

    await redis_service.publish_alert(alert)
    history = await redis_service.get_alert_history(limit=5)
    assert any(a.event_id == "test_alert_1" for a in history)
