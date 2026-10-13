import base64
import logging
from datetime import datetime, timezone
from typing import Optional
import httpx

from app.config import settings
from app.providers.base import BaseThreatProvider
from app.models.indicator import IndicatorType
from app.models.threat import ThreatRecord, VerdictEnum

logger = logging.getLogger("virustotal_provider")


class VirusTotalProvider(BaseThreatProvider):
    BASE_URL = "https://www.virustotal.com/api/v3"

    @property
    def name(self) -> str:
        return "virustotal"

    def _get_url_id(self, url: str) -> str:
        # VirusTotal v3 URL identifier is base64 encoded URL without trailing '='
        return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")

    async def lookup(self, indicator: str, indicator_type: IndicatorType, original_indicator: str) -> ThreatRecord:
        now_iso = datetime.now(timezone.utc).isoformat()

        if not settings.VIRUSTOTAL_API_KEY:
            logger.warning("VirusTotal lookup attempted without configured API key.")
            return ThreatRecord(
                indicator=indicator,
                original_indicator=original_indicator,
                indicator_type=indicator_type,
                verdict=VerdictEnum.UNAVAILABLE,
                malicious=False,
                threat_score=0,
                confidence=0.0,
                categories=["api_key_missing"],
                source=self.name,
                first_seen=None,
                last_seen=None,
                checked_at=now_iso,
                ttl_seconds=60,
                description="VirusTotal API credentials are not configured on server"
            )

        headers = {
            "x-apikey": settings.VIRUSTOTAL_API_KEY,
            "Accept": "application/json",
            "User-Agent": "RedisThreatIntelCache/1.0"
        }

        # Build endpoint according to indicator type
        if indicator_type == IndicatorType.IP:
            endpoint = f"{self.BASE_URL}/ip_addresses/{indicator}"
        elif indicator_type == IndicatorType.DOMAIN:
            endpoint = f"{self.BASE_URL}/domains/{indicator}"
        elif indicator_type == IndicatorType.URL:
            url_id = self._get_url_id(indicator)
            endpoint = f"{self.BASE_URL}/urls/{url_id}"
        else:
            raise ValueError(f"Unsupported indicator type: {indicator_type}")

        try:
            async with httpx.AsyncClient(timeout=settings.VIRUSTOTAL_TIMEOUT_SECONDS) as client:
                response = await client.get(endpoint, headers=headers)

                if response.status_code == 401:
                    logger.error("VirusTotal API authentication failed (HTTP 401).")
                    return ThreatRecord(
                        indicator=indicator,
                        original_indicator=original_indicator,
                        indicator_type=indicator_type,
                        verdict=VerdictEnum.UNAVAILABLE,
                        malicious=False,
                        threat_score=0,
                        confidence=0.0,
                        categories=["authentication_failure"],
                        source=self.name,
                        first_seen=None,
                        last_seen=None,
                        checked_at=now_iso,
                        ttl_seconds=60,
                        description="VirusTotal API key is invalid or rejected by provider"
                    )

                if response.status_code == 429:
                    logger.warning("VirusTotal API rate limit / quota exceeded (HTTP 429).")
                    return ThreatRecord(
                        indicator=indicator,
                        original_indicator=original_indicator,
                        indicator_type=indicator_type,
                        verdict=VerdictEnum.UNAVAILABLE,
                        malicious=False,
                        threat_score=0,
                        confidence=0.0,
                        categories=["rate_limit_exceeded"],
                        source=self.name,
                        first_seen=None,
                        last_seen=None,
                        checked_at=now_iso,
                        ttl_seconds=120,
                        description="VirusTotal query rate limit or monthly quota exceeded"
                    )

                if response.status_code == 404:
                    # Indicator not found in VirusTotal dataset
                    return ThreatRecord(
                        indicator=indicator,
                        original_indicator=original_indicator,
                        indicator_type=indicator_type,
                        verdict=VerdictEnum.UNKNOWN,
                        malicious=False,
                        threat_score=0,
                        confidence=0.0,
                        categories=["unindexed"],
                        source=self.name,
                        first_seen=None,
                        last_seen=None,
                        checked_at=now_iso,
                        ttl_seconds=settings.TTL_UNKNOWN_SECONDS,
                        description="Indicator not indexed in VirusTotal intelligence dataset"
                    )

                response.raise_for_status()
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})

                # Analysis stats
                stats = attributes.get("last_analysis_stats", {})
                malicious_cnt = stats.get("malicious", 0)
                suspicious_cnt = stats.get("suspicious", 0)
                harmless_cnt = stats.get("harmless", 0)
                undetected_cnt = stats.get("undetected", 0)
                total_engines = malicious_cnt + suspicious_cnt + harmless_cnt + undetected_cnt

                if total_engines > 0:
                    threat_score = int(min(100, round(((malicious_cnt + 0.5 * suspicious_cnt) / total_engines) * 100)))
                    confidence = round(min(1.0, total_engines / 60.0), 2)
                else:
                    threat_score = 0
                    confidence = 0.0

                # Categories
                raw_cats = attributes.get("categories", {})
                categories = list(set(raw_cats.values())) if isinstance(raw_cats, dict) else []
                if malicious_cnt > 0 and not categories:
                    categories.append("malicious")

                # Verdict logic
                if malicious_cnt >= 2 or threat_score >= 20:
                    verdict = VerdictEnum.MALICIOUS
                    is_malicious = True
                elif harmless_cnt > 0 and malicious_cnt == 0 and suspicious_cnt == 0:
                    verdict = VerdictEnum.BENIGN
                    is_malicious = False
                elif total_engines > 0 and malicious_cnt == 0 and suspicious_cnt <= 1:
                    verdict = VerdictEnum.BENIGN
                    is_malicious = False
                else:
                    verdict = VerdictEnum.UNKNOWN
                    is_malicious = False

                first_submission = attributes.get("first_submission_date")
                last_analysis = attributes.get("last_analysis_date")

                first_seen_str = datetime.fromtimestamp(first_submission, tz=timezone.utc).isoformat() if first_submission else None
                last_seen_str = datetime.fromtimestamp(last_analysis, tz=timezone.utc).isoformat() if last_analysis else None

                ttl = settings.TTL_MALICIOUS_SECONDS if is_malicious else (
                    settings.TTL_BENIGN_SECONDS if verdict == VerdictEnum.BENIGN else settings.TTL_UNKNOWN_SECONDS
                )

                return ThreatRecord(
                    indicator=indicator,
                    original_indicator=original_indicator,
                    indicator_type=indicator_type,
                    verdict=verdict,
                    malicious=is_malicious,
                    threat_score=threat_score,
                    confidence=confidence,
                    categories=categories,
                    source=self.name,
                    first_seen=first_seen_str,
                    last_seen=last_seen_str,
                    checked_at=now_iso,
                    ttl_seconds=ttl,
                    description=f"VirusTotal intelligence ({malicious_cnt}/{total_engines} security vendors flagged malicious)"
                )

        except (httpx.TimeoutException, httpx.NetworkError) as e:
            logger.error(f"VirusTotal connection timeout or network outage: {e}")
            return ThreatRecord(
                indicator=indicator,
                original_indicator=original_indicator,
                indicator_type=indicator_type,
                verdict=VerdictEnum.UNAVAILABLE,
                malicious=False,
                threat_score=0,
                confidence=0.0,
                categories=["network_timeout"],
                source=self.name,
                first_seen=None,
                last_seen=None,
                checked_at=now_iso,
                ttl_seconds=60,
                description=f"VirusTotal external provider unreachable: {str(e)}"
            )
        except Exception as e:
            logger.error(f"Unexpected error querying VirusTotal: {e}")
            return ThreatRecord(
                indicator=indicator,
                original_indicator=original_indicator,
                indicator_type=indicator_type,
                verdict=VerdictEnum.UNAVAILABLE,
                malicious=False,
                threat_score=0,
                confidence=0.0,
                categories=["provider_error"],
                source=self.name,
                first_seen=None,
                last_seen=None,
                checked_at=now_iso,
                ttl_seconds=60,
                description=f"VirusTotal provider query failure: {str(e)}"
            )
