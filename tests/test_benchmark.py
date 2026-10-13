import pytest
from benchmarks.benchmark import ThreatIntelligenceBenchmark


@pytest.mark.asyncio
async def test_benchmark_execution():
    bench = ThreatIntelligenceBenchmark(sample_size=8)
    results = await bench.run()

    assert "cold_cache" in results
    assert "warm_cache" in results
    assert "comparison" in results

    assert results["cold_cache"]["sample_count"] == 8
    assert results["warm_cache"]["sample_count"] == 8
    assert results["warm_cache"]["cache_hit_rate_pct"] == 100.0
    assert results["comparison"]["requests_avoided_count"] == 8
    assert results["comparison"]["latency_reduction_factor"] >= 1.0
