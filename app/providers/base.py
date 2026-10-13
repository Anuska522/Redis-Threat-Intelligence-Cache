from abc import ABC, abstractmethod
from app.models.indicator import IndicatorType
from app.models.threat import ThreatRecord


class BaseThreatProvider(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the threat intelligence provider."""
        pass

    @abstractmethod
    async def lookup(self, indicator: str, indicator_type: IndicatorType, original_indicator: str) -> ThreatRecord:
        """Fetch threat intelligence for an indicator."""
        pass
