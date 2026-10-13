import pytest
from httpx import AsyncClient
from app.config import settings


@pytest.mark.asyncio
async def test_health_endpoint(async_client: AsyncClient):
    resp = await async_client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "redis" in data
    assert "cti_provider" in data


@pytest.mark.asyncio
async def test_check_endpoint_get_and_post(async_client: AsyncClient):
    # GET
    resp_get = await async_client.get("/api/check?indicator=8.8.8.8")
    assert resp_get.status_code == 200
    assert resp_get.json()["verdict"] == "benign"

    # POST
    resp_post = await async_client.post("/api/check", json={"indicator": "203.0.113.25"})
    assert resp_post.status_code == 200
    assert resp_post.json()["verdict"] == "malicious"


@pytest.mark.asyncio
async def test_check_endpoint_invalid_input(async_client: AsyncClient):
    resp = await async_client.post("/api/check", json={"indicator": "not-a-valid-ip-or-domain"})
    assert resp.status_code == 400
    assert "detail" in resp.json()


@pytest.mark.asyncio
async def test_stats_endpoint(async_client: AsyncClient):
    resp = await async_client.get("/api/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_lookups" in data
    assert "cache_hit_rate_pct" in data
    assert "avoided_requests" in data


@pytest.mark.asyncio
async def test_blacklist_unauthorized(async_client: AsyncClient):
    resp = await async_client.post("/api/blacklist", json={
        "indicator": "198.51.100.77",
        "reason": "Unauthorized attempt"
    })
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_blacklist_authorized_workflow(async_client: AsyncClient):
    headers = {"X-Admin-Key": settings.ADMIN_API_KEY}
    test_ind = "198.51.100.88"

    # Add
    add_resp = await async_client.post(
        "/api/blacklist",
        json={"indicator": test_ind, "reason": "Test block"},
        headers=headers
    )
    assert add_resp.status_code == 201

    # List
    list_resp = await async_client.get("/api/blacklist")
    assert list_resp.status_code == 200
    assert any(item["indicator"] == test_ind for item in list_resp.json())

    # Delete
    del_resp = await async_client.delete(f"/api/blacklist/{test_ind}", headers=headers)
    assert del_resp.status_code == 200


@pytest.mark.asyncio
async def test_settings_get_and_post(async_client: AsyncClient):
    # GET settings (sanitized)
    resp = await async_client.get("/api/settings")
    assert resp.status_code == 200
    assert "ttl_malicious_seconds" in resp.json()

    # Unauthorized POST
    post_unauth = await async_client.post("/api/settings", json={"alert_risk_threshold": 80})
    assert post_unauth.status_code == 401

    # Authorized POST
    headers = {"X-Admin-Key": settings.ADMIN_API_KEY}
    post_auth = await async_client.post(
        "/api/settings",
        json={"alert_risk_threshold": 80},
        headers=headers
    )
    assert post_auth.status_code == 200


@pytest.mark.asyncio
async def test_serve_dashboard(async_client: AsyncClient):
    resp = await async_client.get("/")
    assert resp.status_code == 200
    assert "Real-Time Threat Intelligence Cache" in resp.text
