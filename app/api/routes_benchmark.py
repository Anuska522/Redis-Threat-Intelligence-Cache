from fastapi import APIRouter, HTTPException
from app.models.api_models import BenchmarkRunRequest
from benchmarks.benchmark import ThreatIntelligenceBenchmark

router = APIRouter(prefix="/api/benchmark", tags=["Benchmarking"])


@router.post("/run", summary="Execute automated latency and cache performance benchmark")
async def run_benchmark(request: BenchmarkRunRequest):
    try:
        benchmark = ThreatIntelligenceBenchmark(sample_size=request.sample_size)
        results = await benchmark.run()
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Benchmark execution failed: {str(e)}")
