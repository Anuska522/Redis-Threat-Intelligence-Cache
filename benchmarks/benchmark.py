import sys
from pathlib import Path

# Add project root to path for direct script invocation
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import asyncio
import time
import statistics
import json
from typing import List, Dict, Any

from app.services.redis_service import redis_service
from app.services.lookup_service import lookup_service
from app.models.threat import LookupResponse


class ThreatIntelligenceBenchmark:
    def __init__(self, sample_size: int = 20):
        self.sample_size = sample_size
        self.fixtures = self._load_fixtures()

    def _load_fixtures(self) -> List[str]:
        data_file = REPO_ROOT / "data" / "demo_threats.json"
        if not data_file.exists():
            return [
                "203.0.113.25", "8.8.8.8", "1.1.1.1",
                "phish-secure-banking-login.com", "github.com", "microsoft.com",
                "http://phish-secure-banking-login.com/auth/login.php?session=steal",
                "https://github.com/torvalds/linux"
            ]
        with open(data_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return [item["indicator"] for item in data.get("indicators", [])]

    async def run(self) -> Dict[str, Any]:
        await redis_service.connect()
        test_indicators = (self.fixtures * ((self.sample_size // len(self.fixtures)) + 1))[:self.sample_size]

        # -------------------------------------------------------------
        # Phase 1: Cold Cache Run (force refresh queries intelligence source)
        # -------------------------------------------------------------
        cold_latencies: List[float] = []
        cold_hits = 0
        cold_misses = 0

        cold_start_all = time.perf_counter()
        for indicator in test_indicators:
            start = time.perf_counter()
            resp: LookupResponse = await lookup_service.lookup(indicator, force_refresh=True)
            latency_ms = (time.perf_counter() - start) * 1000.0
            cold_latencies.append(latency_ms)
            if resp.cache_status == "hit":
                cold_hits += 1
            else:
                cold_misses += 1
        cold_total_duration = time.perf_counter() - cold_start_all

        # -------------------------------------------------------------
        # Phase 2: Warm Cache Run (reads directly from Redis cache hashes)
        # -------------------------------------------------------------
        warm_latencies: List[float] = []
        warm_hits = 0
        warm_misses = 0

        warm_start_all = time.perf_counter()
        for indicator in test_indicators:
            start = time.perf_counter()
            resp: LookupResponse = await lookup_service.lookup(indicator, force_refresh=False)
            latency_ms = (time.perf_counter() - start) * 1000.0
            warm_latencies.append(latency_ms)
            if resp.cache_status == "hit":
                warm_hits += 1
            else:
                warm_misses += 1
        warm_total_duration = time.perf_counter() - warm_start_all

        def calc_metrics(latencies: List[float], hits: int, misses: int, total_duration: float = None):
            sorted_lat = sorted(latencies)
            n = len(sorted_lat)
            avg_lat = statistics.mean(sorted_lat) if n > 0 else 0.0
            p50 = statistics.median(sorted_lat) if n > 0 else 0.0
            p95 = sorted_lat[int(0.95 * (n - 1))] if n > 1 else sorted_lat[-1]
            p99 = sorted_lat[int(0.99 * (n - 1))] if n > 1 else sorted_lat[-1]
            hit_rate = (hits / n * 100.0) if n > 0 else 0.0
            miss_rate = (misses / n * 100.0) if n > 0 else 0.0
            throughput = (n / total_duration) if (total_duration and total_duration > 0) else 0.0

            return {
                "sample_count": n,
                "avg_latency_ms": round(avg_lat, 3),
                "p50_latency_ms": round(p50, 3),
                "p95_latency_ms": round(p95, 3),
                "p99_latency_ms": round(p99, 3),
                "cache_hits": hits,
                "cache_misses": misses,
                "cache_hit_rate_pct": round(hit_rate, 2),
                "cache_miss_rate_pct": round(miss_rate, 2),
                "throughput_req_sec": round(throughput, 2)
            }

        cold_results = calc_metrics(cold_latencies, cold_hits, cold_misses, cold_total_duration)
        warm_results = calc_metrics(warm_latencies, warm_hits, warm_misses, warm_total_duration)

        speedup = (cold_results["avg_latency_ms"] / warm_results["avg_latency_ms"]) if warm_results["avg_latency_ms"] > 0 else 1.0
        requests_avoided = warm_hits

        return {
            "benchmark_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "dataset_mode": lookup_service.active_provider_name,
            "sample_size": len(test_indicators),
            "cold_cache": cold_results,
            "warm_cache": warm_results,
            "comparison": {
                "latency_reduction_factor": round(speedup, 2),
                "requests_avoided_count": requests_avoided,
                "latency_reduction_pct": round(
                    max(0.0, (1.0 - (warm_results["avg_latency_ms"] / max(cold_results["avg_latency_ms"], 0.001))) * 100.0), 2
                )
            }
        }


async def main():
    bench = ThreatIntelligenceBenchmark(sample_size=30)
    res = await bench.run()
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
