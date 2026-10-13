import json
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from app.providers.base import BaseThreatProvider
from app.models.indicator import IndicatorType
from app.models.threat import ThreatRecord, VerdictEnum

logger = logging.getLogger("demo_provider")


class LocalDemoProvider(BaseThreatProvider):
    def __init__(self, dataset_path: Optional[str] = None):
        if dataset_path:
            self.dataset_file = Path(dataset_path)
        else:
            self.dataset_file = Path(__file__).resolve().parent.parent.parent / "data" / "demo_threats.json"
        self._indicators: Dict[str, Dict[str, Any]] = {}
        self._load_dataset()

    @property
    def name(self) -> str:
        return "local_cti"

    def _load_dataset(self) -> None:
        if not self.dataset_file.exists():
            logger.warning(f"Demo threat dataset not found at {self.dataset_file}")
            return

        try:
            with open(self.dataset_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data.get("indicators", []):
                    key = item.get("indicator", "").strip().lower()
                    if key:
                        self._indicators[key] = item
            logger.info(f"Loaded {len(self._indicators)} documented threat fixtures from {self.dataset_file}")
        except Exception as e:
            logger.error(f"Error loading demo threats dataset: {e}")

    async def lookup(self, indicator: str, indicator_type: IndicatorType, original_indicator: str) -> ThreatRecord:
        now_iso = datetime.now(timezone.utc).isoformat()
        lookup_key = indicator.strip().lower()

        # Check exact fixture match
        fixture = self._indicators.get(lookup_key)
        if not fixture and indicator_type == IndicatorType.URL:
            # Also try stripped URL without trailing slash or lowercase
            fixture = self._indicators.get(lookup_key.rstrip("/"))

        if fixture:
            verdict_str = fixture.get("verdict", "unknown").lower()
            verdict = VerdictEnum(verdict_str) if verdict_str in [v.value for v in VerdictEnum] else VerdictEnum.UNKNOWN
            is_malicious = bool(fixture.get("malicious", verdict == VerdictEnum.MALICIOUS))

            return ThreatRecord(
                indicator=indicator,
                original_indicator=original_indicator,
                indicator_type=indicator_type,
                verdict=verdict,
                malicious=is_malicious,
                threat_score=int(fixture.get("threat_score", 90 if is_malicious else 0)),
                confidence=float(fixture.get("confidence", 0.95)),
                categories=fixture.get("categories", []),
                source=self.name,
                first_seen=fixture.get("first_seen", "2026-08-01T00:00:00Z"),
                last_seen=fixture.get("last_seen", now_iso),
                checked_at=now_iso,
                ttl_seconds=7200 if is_malicious else 3600,
                description=fixture.get("description", "Demonstration dataset fixture")
            )

        # If not present in demonstration fixtures, return UNKNOWN (never assume benign without data)
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
            ttl_seconds=300,
            description="Indicator not present in local threat intelligence repository"
        )
