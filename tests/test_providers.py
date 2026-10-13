import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx
from app.providers.demo_provider import LocalDemoProvider
from app.providers.virustotal import VirusTotalProvider
from app.models.indicator import IndicatorType
from app.models.threat import VerdictEnum
from app.config import settings


@pytest.mark.asyncio
async def test_demo_provider_known_fixtures():
    provider = LocalDemoProvider()

    # Malicious fixture
    res_mal = await provider.lookup("203.0.113.25", IndicatorType.IP, "203.0.113.25")
    assert res_mal.verdict == VerdictEnum.MALICIOUS
    assert res_mal.malicious is True
    assert res_mal.threat_score >= 90
    assert "botnet" in res_mal.categories

    # Benign fixture
    res_ben = await provider.lookup("8.8.8.8", IndicatorType.IP, "8.8.8.8")
    assert res_ben.verdict == VerdictEnum.BENIGN
    assert res_ben.malicious is False
    assert res_ben.threat_score == 0


@pytest.mark.asyncio
async def test_demo_provider_unknown_indicator():
    provider = LocalDemoProvider()
    res = await provider.lookup("99.88.77.66", IndicatorType.IP, "99.88.77.66")
    # Must NOT assume clean or benign! Must be UNKNOWN
    assert res.verdict == VerdictEnum.UNKNOWN
    assert res.malicious is False
    assert res.threat_score == 0
    assert "unindexed" in res.categories


@pytest.mark.asyncio
async def test_virustotal_missing_api_key():
    with patch.object(settings, "VIRUSTOTAL_API_KEY", ""):
        provider = VirusTotalProvider()
        res = await provider.lookup("8.8.8.8", IndicatorType.IP, "8.8.8.8")
        assert res.verdict == VerdictEnum.UNAVAILABLE
        assert "api_key_missing" in res.categories


@pytest.mark.asyncio
async def test_virustotal_rate_limit_handling():
    with patch.object(settings, "VIRUSTOTAL_API_KEY", "dummy_key"):
        provider = VirusTotalProvider()
        mock_response = MagicMock(status_code=429)

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            res = await provider.lookup("8.8.8.8", IndicatorType.IP, "8.8.8.8")
            assert res.verdict == VerdictEnum.UNAVAILABLE
            assert "rate_limit_exceeded" in res.categories


@pytest.mark.asyncio
async def test_virustotal_malicious_detection():
    with patch.object(settings, "VIRUSTOTAL_API_KEY", "dummy_key"):
        provider = VirusTotalProvider()
        mock_data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 15,
                        "suspicious": 2,
                        "harmless": 40,
                        "undetected": 5
                    },
                    "categories": {
                        "VendorA": "phishing"
                    }
                }
            }
        }
        mock_response = MagicMock(status_code=200)
        mock_response.json.return_value = mock_data
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            res = await provider.lookup("bad-phish.com", IndicatorType.DOMAIN, "bad-phish.com")
            assert res.verdict == VerdictEnum.MALICIOUS
            assert res.malicious is True
            assert res.threat_score > 20
