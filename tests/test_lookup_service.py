import pytest
from app.services.lookup_service import lookup_service
from app.services.redis_service import redis_service
from app.models.threat import VerdictEnum
from app.models.indicator import IndicatorType


@pytest.mark.asyncio
async def test_cache_miss_followed_by_cache_hit():
    await redis_service.connect()
    test_indicator = "203.0.113.25"

    # Ensure key is flushed first to guarantee cold cache
    await redis_service._client.delete(f"ti:ip:{test_indicator}")

    # First lookup: Must be Cache Miss
    resp1 = await lookup_service.lookup(test_indicator, force_refresh=False)
    assert resp1.cache_status == "miss"
    assert resp1.verdict == VerdictEnum.MALICIOUS
    assert resp1.threat_score >= 90
    assert resp1.source == "local_cti"

    # Second lookup: Must be Cache Hit from Redis Hash
    resp2 = await lookup_service.lookup(test_indicator, force_refresh=False)
    assert resp2.cache_status == "hit"
    assert resp2.verdict == VerdictEnum.MALICIOUS
    assert resp2.threat_score == resp1.threat_score
    assert resp2.source == "redis_cache"
    assert resp2.ttl_remaining is not None
    assert resp2.ttl_remaining > 0


@pytest.mark.asyncio
async def test_blacklist_immediate_interception():
    await redis_service.connect()
    blocked_domain = "evil-manual-blacklist.com"

    # Add to administrative blacklist
    await redis_service.add_to_blacklist(
        IndicatorType.DOMAIN,
        blocked_domain,
        reason="Manual interception test"
    )

    # Perform lookup: should be intercepted as blacklisted
    resp = await lookup_service.lookup(blocked_domain)
    assert resp.is_blacklisted is True
    assert resp.verdict == VerdictEnum.MALICIOUS
    assert resp.threat_score == 100
    assert resp.source == "administrative_blacklist"

    # Cleanup
    await redis_service.remove_from_blacklist(IndicatorType.DOMAIN, blocked_domain)


@pytest.mark.asyncio
async def test_force_refresh_bypasses_cache():
    await redis_service.connect()
    test_ip = "8.8.8.8"

    # Populate cache
    await lookup_service.lookup(test_ip, force_refresh=False)

    # Force refresh must produce miss on provider
    resp_refresh = await lookup_service.lookup(test_ip, force_refresh=True)
    assert resp_refresh.cache_status == "miss"
    assert resp_refresh.source == "local_cti"
