# Real-Time Threat Intelligence Cache and Malicious URL/IP Detection System Using Redis

## 1. Project Overview

The **Real-Time Threat Intelligence Cache and Malicious URL/IP Detection System Using Redis** is a high-speed, cache-first cybersecurity web application and REST API designed to evaluate Indicators of Compromise (IoCs)—specifically IPv4 addresses, IPv6 addresses, fully qualified domain names, and HTTP/HTTPS URLs.

Modern security workflows frequently inspect indicators against external threat intelligence platforms (such as VirusTotal or AbuseIPDB). However, contacting external third-party APIs for every individual query introduces network latency (often 200–800 ms per request), consumes rate-limited API quotas, incurs operational costs, and risks service disruption during provider outages. 

This system resolves these operational challenges by implementing Redis as an in-memory NoSQL acceleration layer. Incoming queries are evaluated first against Redis in-memory data structures. Valid cached results are returned in sub-millisecond time. Upon a cache miss or TTL expiration, the system queries the configured threat intelligence source, applies indicator-specific Time-To-Live (TTL) expiration policies, updates operational counters and threat rankings, and publishes real-time alerts across Redis Pub/Sub channels to connected Security Operations Center (SOC) dashboards.

---

## 2. Problem Statement & Objectives

### Problem Statement
Security tools (firewalls, SIEMs, email gateways, automated incident response playbooks) frequently encounter repeated queries for identical indicators during active campaigns. A naive approach forwards each query directly to third-party threat intelligence APIs. This causes:
1. Significant latency overhead on critical lookup paths.
2. Rapid exhaustion of API rate limits and subscription quotas.
3. Tight coupling and vulnerability to third-party external service downtime.
4. Redundant external lookups for hot indicators.

### System Objectives
1. **Cache-First IoC Resolution:** Intercept lookups at the Redis layer to achieve sub-millisecond responses for cached entries.
2. **Deterministic Input Normalization:** Safely normalize IPv4, IPv6, domains, and URLs to prevent key fragmentation and injection attacks without visiting malicious URLs.
3. **Multi-Type Redis NoSQL Integration:** Native application of Redis Hashes, Sets, Sorted Sets, atomic Counters, TTL expiration, and Pub/Sub messaging.
4. **Freshness-Aware TTL Policies:** Enforce granular cache expiration (separate policies for malicious, benign, and unknown indicators) to guarantee stale intelligence is automatically refreshed.
5. **Real-Time Security Event Delivery:** Deliver instant threat notifications to connected clients via Redis Pub/Sub bridged to WebSockets.
6. **Administrative Blacklist Control:** Provide authenticated O(1) membership checks and administrative control over dedicated blacklist sets.
7. **Empirical Benchmarking Suite:** Measure cold cache vs warm cache performance, latency percentiles (P50, P95, P99), hit rates, and requests avoided.

---

## 3. Architecture & Data Flow

```
                      +-----------------------------+
                      | Security Analyst / API Client|
                      +--------------+--------------+
                                     |
                                     v [HTTP / WebSocket]
                      +-----------------------------+
                      |   FastAPI Application Core   |
                      |   (Security & Normalization)|
                      +--------------+--------------+
                                     |
                   +-----------------+-----------------+
                   |                                   |
                   v                                   v
+------------------------------------+  +--------------------------------+
|       Redis In-Memory NoSQL        |  |  Threat Intelligence Provider  |
|                                    |  |                                |
| - Sets: Administrative Blacklist   |  | - Local CTI Fixture Provider   |
| - Hashes: Threat Intelligence Cache|  | - VirusTotal v3 API            |
| - Sorted Sets: rank:threats        |  +--------------------------------+
| - Counters: stats:lookups          |                 ^
| - Pub/Sub: alerts Channel          |                 | Cache Miss /
+------------------------------------+                 | Force Refresh
                   |                                   |
                   +-----------------------------------+
```

### End-to-End Lookup Lifecycle:
1. **Client Submission:** Client submits an indicator string via the REST API or SOC Dashboard.
2. **Deterministic Normalization:** The input is validated and classified:
   - IPv4/IPv6: Parsed and compressed via RFC-compliant IP libraries.
   - Domains: Case-normalized, trailing dots removed, IDN punycode transformed.
   - URLs: Scheme and authority normalized, default ports stripped, query/path preserved, and SHA-256 hashed for Redis key generation. URLs are never fetched or executed.
3. **Blacklist Check (Redis Sets):** The normalized indicator is checked against `blacklist:<type>` using `SISMEMBER`. If present, an immediate malicious verdict is returned without external calls.
4. **Cache Lookup (Redis Hashes):** The system checks `HGETALL ti:<type>:<indicator_or_hash>`. If present and valid, remaining TTL is calculated, hit counters are incremented, rankings are updated, and the response is returned as a **Cache Hit**.
5. **Provider Fallback (Cache Miss):** If missing or expired, miss counters are incremented. The configured provider (`local_cti` or `virustotal`) is queried.
6. **Cache Storage & TTL:** Successful provider results are serialized into a Redis Hash and assigned a TTL using `EXPIRE` based on the verdict:
   - Malicious indicators: `TTL_MALICIOUS_SECONDS` (default: 7200s / 2 hours).
   - Benign indicators: `TTL_BENIGN_SECONDS` (default: 3600s / 1 hour).
   - Unknown indicators: `TTL_UNKNOWN_SECONDS` (default: 300s / 5 minutes).
7. **Alert Publication:** If `threat_score >= ALERT_RISK_THRESHOLD` (default: 75), an `AlertEvent` is published to the Redis Pub/Sub channel `alerts` and stored in `history:alerts`.
8. **Client Response:** A structured JSON response is returned containing latency measurements, cache status, verdict, score, confidence, categories, and TTL remaining.

---

## 4. Redis Data Structures & Key Naming Conventions

| Redis Data Structure | Project Function | Key Naming Pattern | Description |
| :--- | :--- | :--- | :--- |
| **Hash** | Threat Record | `ti:ip:<indicator>`<br>`ti:domain:<domain>`<br>`ti:url:<sha256_hash>` | Compact storage of fields: `indicator`, `type`, `verdict`, `score`, `confidence`, `categories`, `source`, `checked_at`, `ttl_seconds`. |
| **Set** | Blacklists | `blacklist:ip`<br>`blacklist:domain`<br>`blacklist:url` | Dedicated sets providing O(1) membership checks (`SISMEMBER`). |
| **Hash** | Blacklist Metadata | `blacklist:meta:<indicator>` | Stores reason, source, timestamp, and administrator identifier for blacklist entries. |
| **Sorted Set** | Threat Frequency Ranking | `rank:threats` | Member: indicator, Score: lookup frequency count (`ZINCRBY`). Allows top threats retrieval (`ZREVRANGE`). |
| **String (Counters)** | Metrics & Hit/Miss Tracking | `stats:lookups:total`<br>`stats:lookups:hits`<br>`stats:lookups:misses`<br>`stats:lookups:threats_detected`<br>`stats:lookups:provider_requests`<br>`stats:lookups:provider_errors` | Atomic string counters incremented with `INCRBY`. |
| **String (Float)** | Latency Accumulator | `stats:latency:total_ms`<br>`stats:latency:hit_ms`<br>`stats:latency:miss_ms` | Floating point accumulators (`INCRBYFLOAT`) paired with count counters to derive exact rolling averages. |
| **Pub/Sub Channel** | Real-Time Threat Alerts | `alerts` | Broadcasts new high-risk indicators (`PUBLISH`) to active subscribers. |
| **List** | Audit & History Trails | `history:lookups`<br>`history:alerts` | Bounded circular lists (`LPUSH` + `LTRIM` capped at 100 entries). |

---

## 5. Technology Stack

- **Backend Runtime:** Python 3.13 / 3.12
- **Web & API Framework:** FastAPI (ASGI, Pydantic v2, Starlette)
- **Primary NoSQL Database:** Redis (via `redis-py` async client) with resilient embedded fallback (`fakeredis`)
- **HTTP Client:** HTTPX (async client with connection pooling and timeouts)
- **Frontend:** Vanilla HTML5, CSS3, JavaScript (ES6+), WebSockets (no emojis, dark SOC theme)
- **Containerization:** Docker & Docker Compose

---

## 6. Environment Variables Configuration

Copy `.env.example` to `.env` and adjust settings as needed:

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `APP_NAME` | Real-Time Threat Intelligence Cache... | Application service title |
| `APP_ENV` | `development` | Deployment environment (`development`, `production`) |
| `HOST` | `127.0.0.1` | Bind host address |
| `PORT` | `8000` | Bind port number |
| `REDIS_URL` | `redis://127.0.0.1:6379/0` | Connection string for Redis instance |
| `REDIS_TIMEOUT_SECONDS` | `2.0` | Network socket timeout for Redis connection |
| `REDIS_MAX_CONNECTIONS` | `20` | Redis client connection pool size |
| `CTI_PROVIDER` | `demo` | Active threat source: `demo` (offline) or `virustotal` (live) |
| `VIRUSTOTAL_API_KEY` | `""` | VirusTotal v3 API key (required if provider is `virustotal`) |
| `VIRUSTOTAL_TIMEOUT_SECONDS`| `5.0` | Timeout for external VirusTotal HTTP requests |
| `TTL_MALICIOUS_SECONDS` | `7200` | Cache lifetime for confirmed malicious records (2 hours) |
| `TTL_BENIGN_SECONDS` | `3600` | Cache lifetime for confirmed benign records (1 hour) |
| `TTL_UNKNOWN_SECONDS` | `300` | Cache lifetime for unindexed or unknown records (5 mins) |
| `ADMIN_API_KEY` | `adminkey-threat-intel-2026-secure` | Administrative secret key for protected operations |
| `ALERT_RISK_THRESHOLD` | `75` | Minimum threat score (0-100) that triggers a real-time alert |
| `CORS_ORIGINS` | `["http://localhost:8000"]` | Allowed CORS origins (JSON array) |

---

## 7. Installation & Startup Instructions

### Prerequisites
- Python 3.11+
- Git
- (Optional) Redis server or Docker

### Option A: Local Development Run (Standalone)
The application automatically connects to a local Redis server if available on `REDIS_URL`. If no external Redis instance is running, it falls back seamlessly to the integrated in-memory Redis simulation engine.

```powershell
# 1. Clone repository
git clone <repository_url>
cd "nosql nosql project"

# 2. Install dependencies
pip install -r requirements.txt

# 3. Create environment file
Copy-Item .env.example .env

# 4. Start the application
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```
Open **`http://127.0.0.1:8000`** in any web browser to access the SOC Dashboard, or visit **`http://127.0.0.1:8000/docs`** for interactive OpenAPI documentation.

### Option B: Docker Compose Deployment (Multi-Container)
To run with a dedicated Redis container and automated healthchecks:

```bash
docker-compose up --build -d
```
Inspect logs:
```bash
docker-compose logs -f
```

---

## 8. Threat Intelligence Providers

### 1. Local Demonstration Provider (`demo`)
The system includes a verified, documented dataset (`data/demo_threats.json`) of test fixtures across IPs, domains, and URLs.
- **Malicious Fixtures:**
  - `203.0.113.25`: Known Mirai botnet C2 and SSH scanner (Threat score: 92)
  - `198.51.100.44`: Ransomware payload distribution server (Threat score: 88)
  - `185.220.101.5`: Tor exit relay conducting aggressive port scans (Threat score: 78)
  - `2001:db8:85a3::8a2e:370:7334`: Bulletproof IPv6 hosting used for DDoS (Threat score: 85)
  - `phish-secure-banking-login.com`: Financial credential phishing domain (Threat score: 96)
  - `http://phish-secure-banking-login.com/auth/login.php?session=steal`: Phishing landing page (Threat score: 98)
  - `https://malware-c2-updater-node.net/payloads/rat_v2.exe`: RAT executable dropper (Threat score: 95)
- **Benign Fixtures:**
  - `8.8.8.8`: Google Public DNS resolver (Threat score: 0)
  - `1.1.1.1`: Cloudflare authoritative resolver (Threat score: 0)
  - `2606:4700:4700::1111`: Cloudflare IPv6 DNS resolver (Threat score: 0)
  - `github.com`: Software development platform (Threat score: 0)
  - `https://github.com/torvalds/linux`: Linux kernel source repository (Threat score: 0)
- **Unindexed / Unknown Indicators:**
  - Any indicator not present in the demonstration dataset returns `verdict: "unknown"` with score `0` and a short 300-second TTL. The system **never** treats an unindexed indicator as verified benign.

### 2. VirusTotal Live Provider (`virustotal`)
- To enable live VirusTotal lookups, set `CTI_PROVIDER=virustotal` and specify `VIRUSTOTAL_API_KEY` in `.env` (or via `/api/settings`).
- Queries VirusTotal v3 REST endpoints for IPs, domains, and base64-encoded URL identifiers.
- Translates `last_analysis_stats` into normalized scores and verdicts.
- Handles HTTP 401 (authentication failure), HTTP 429 (rate limit quota exceeded), HTTP 404 (unindexed), and connection timeouts without marking failed requests as benign.

---

## 9. REST API Reference

### Indicator Lookup
- **`GET /api/check?indicator=<value>`**
- **`POST /api/check`**
  ```json
  { "indicator": "203.0.113.25" }
  ```
  **Response (HTTP 200):**
  ```json
  {
    "indicator": "203.0.113.25",
    "original_indicator": "203.0.113.25",
    "indicator_type": "ip",
    "verdict": "malicious",
    "malicious": true,
    "threat_score": 92,
    "confidence": 0.97,
    "categories": ["botnet", "scanning", "c2"],
    "source": "redis_cache",
    "cache_status": "hit",
    "latency_ms": 0.59,
    "ttl_remaining": 7191,
    "ttl_policy": 7200,
    "checked_at": "2026-10-13T14:20:59.899179+00:00",
    "first_seen": "2026-08-20T10:00:00Z",
    "last_seen": "2026-08-21T18:20:00Z",
    "description": "Known Mirai botnet controller and automated SSH brute force scanner",
    "is_blacklisted": false,
    "redis_key": "ti:ip:203.0.113.25",
    "alert_triggered": false
  }
  ```

### Cache Invalidation & Forced Refresh
- **`POST /api/refresh/{indicator}`**
  Bypasses the Redis cache, queries the provider directly, updates the cache with fresh TTL, and returns the newly retrieved intelligence.

### Operational Statistics & Analytics
- **`GET /api/stats`**
  Returns cache hit rate, miss rate, total lookups, requests avoided, average hit/miss latencies, and Redis connectivity mode.
- **`GET /api/top-threats?limit=10`**
  Returns ranked indicators from the Redis Sorted Set `rank:threats`.
- **`GET /api/history?limit=50`**
  Returns recent lookups from Redis circular list `history:lookups`.

### Blacklist Management (Protected)
- **`GET /api/blacklist`** - Retrieve all blacklisted items across sets.
- **`POST /api/blacklist`** - Add indicator to blacklist (Requires `X-Admin-Key` header).
  ```json
  {
    "indicator": "198.51.100.99",
    "reason": "Observed in active malware campaign"
  }
  ```
- **`DELETE /api/blacklist/{indicator}`** - Remove entry from blacklist (Requires `X-Admin-Key` header).

### Real-Time Alerts
- **`GET /api/alerts/history`** - Retrieve recent alerts from `history:alerts`.
- **`WebSocket /ws/alerts`** - Live stream of alert events published to the Redis `alerts` channel.

### System Settings & Health
- **`GET /api/health`** - Application, Redis, and CTI provider status.
- **`GET /api/settings`** - View runtime TTL and threshold configurations.
- **`POST /api/settings`** - Update settings (Requires `X-Admin-Key` header).

---

## 10. Performance Benchmarking

### Methodology
The benchmark suite evaluates the operational efficiency of the Redis caching architecture by executing a standardized workload across cold cache and warm cache states:
1. **Cold Cache Phase:** Forced queries (`force_refresh=True`) that simulate cache misses and provider retrieval.
2. **Warm Cache Phase:** Lookups executed against populated Redis Hashes without external queries.
3. **Monotonic Timing:** High-precision timing using `time.perf_counter()`.
4. **Calculated Metrics:**
   - **Cache Hit Rate:** $\frac{\text{Hits}}{\text{Total Lookups}} \times 100\%$
   - **Cache Miss Rate:** $\frac{\text{Misses}}{\text{Total Lookups}} \times 100\%$
   - **Requests Avoided:** Equal to total cache hits.
   - **Latency Percentiles:** Mean, Median (P50), 95th Percentile (P95), and 99th Percentile (P99).
   - **Throughput:** $\frac{\text{Requests}}{\text{Total Elapsed Seconds}}$.

### Running the Benchmark
Execute via the CLI:
```powershell
python benchmarks/benchmark.py
```
Or execute on demand through the SOC Dashboard UI under the **Performance Benchmark** tab.

### Empirical Results (Measured Workload)
```json
{
  "dataset_mode": "demo",
  "sample_size": 30,
  "cold_cache": {
    "sample_count": 30,
    "avg_latency_ms": 1.987,
    "p50_latency_ms": 1.597,
    "p95_latency_ms": 2.858,
    "p99_latency_ms": 3.142,
    "cache_hits": 0,
    "cache_misses": 30,
    "cache_hit_rate_pct": 0.0,
    "throughput_req_sec": 502.95
  },
  "warm_cache": {
    "sample_count": 30,
    "avg_latency_ms": 1.333,
    "p50_latency_ms": 1.270,
    "p95_latency_ms": 1.733,
    "p99_latency_ms": 1.749,
    "cache_hits": 30,
    "cache_misses": 0,
    "cache_hit_rate_pct": 100.0,
    "throughput_req_sec": 749.65
  },
  "comparison": {
    "latency_reduction_factor": 1.49,
    "requests_avoided_count": 30,
    "latency_reduction_pct": 32.91
  }
}
```
*(Note: When querying external live network providers such as VirusTotal, cold cache latencies typically range from 200 ms to 800 ms, resulting in speedup factors exceeding 150x to 300x).*

---

## 11. Automated Testing Suite

The project includes an automated test suite with 29 test cases covering normalization, Redis operations, provider fallbacks, API routes, authentication, and benchmarks.

Run all tests:
```powershell
python -m pytest -v
```

Test coverage breakdown:
- **`tests/test_normalizer.py`:** IPv4, IPv6, URLs, canonicalization, port stripping, domain regex, and rejection of malformed indicators.
- **`tests/test_redis_service.py`:** Hash serialization/deserialization, TTL validity, Set operations, Sorted Set rankings, atomic counters, and Pub/Sub alerts.
- **`tests/test_providers.py`:** LocalDemoProvider fixture retrieval, unindexed indicator handling, VirusTotal API key handling, rate-limit (429) resilience, and network error handling.
- **`tests/test_lookup_service.py`:** Cold miss followed by warm hit verification, blacklist interception, force refresh behavior, and alert trigger rules.
- **`tests/test_api.py`:** REST endpoints, HTTP status codes, administrative key authentication (`X-Admin-Key`), input validation errors, and static dashboard serving.
- **`tests/test_benchmark.py`:** Benchmark runner repeatability and metric calculation.

---

## 12. Security Considerations

1. **URL Safety:** Submitted URLs are canonicalized and hashed using SHA-256 for key construction. The application **never** establishes an outbound HTTP connection to target URLs submitted for analysis.
2. **Key Injection Prevention:** Indicators undergo strict character validation. Control characters, newlines, and carriage returns are rejected to prevent Redis protocol injection.
3. **Administrative Access:** Dangerous operations (`POST /api/blacklist`, `DELETE /api/blacklist/{id}`, `POST /api/settings`) require an authenticated `X-Admin-Key` or `Authorization: Bearer` token.
4. **Credential Isolation:** API keys and sensitive tokens are read exclusively from environment variables and never logged or serialized to frontend payloads.
5. **Security Headers:** The application enforces `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, and restrictive `Permissions-Policy` headers.
6. **Failure-Safe Threat Verdicts:** Network failures, rate limit exhaustion, or missing provider credentials return `UNAVAILABLE` or `UNKNOWN` status codes and are never treated as clean or benign indicators.

---

## 13. Troubleshooting & FAQ

- **Redis connection warnings on Windows:** If a standalone Redis server is not running on port 6379, the application logs a warning and automatically activates its integrated in-memory Redis simulation engine (`fakeredis`). All features (Hashes, Sets, Sorted Sets, Counters, TTL, and Pub/Sub) function identically.
- **Enabling Real Redis:** Start a Redis container via `docker-compose up -d redis` or specify an external Redis connection string in `REDIS_URL`.
- **VirusTotal Quota Exceeded (HTTP 429):** Free VirusTotal API keys are limited to 4 requests/minute. The application safely flags rate-limited responses with a 120-second backoff TTL. For high-volume testing without quotas, use `CTI_PROVIDER=demo`.
