# apps/api/threat_intelligence.py
"""
Modular Threat Intelligence Enrichment Layer for FlowCrypid.
Fails safely, caches results, and separates enrichment from detection.
"""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any


@dataclass
class EnrichmentRecord:
    indicator: str
    indicator_type: str  # 'ip' or 'domain'
    reputation: str      # 'malicious', 'suspicious', 'benign', 'unknown', 'unavailable'
    is_malicious: bool
    asn: Optional[int] = None
    organization: Optional[str] = None
    country: Optional[str] = None
    threat_category: Optional[str] = None
    source: str = "Unassigned"
    confidence: float = 0.0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    timestamp: float = 0.0
    is_stale: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ThreatIntelProvider(ABC):
    @abstractmethod
    def lookup(self, indicator: str, indicator_type: str) -> Optional[EnrichmentRecord]:
        pass


class MockThreatIntelProvider(ThreatIntelProvider):
    """Mock provider for testing without external network dependencies."""

    def __init__(self, known_indicators: Optional[Dict[str, dict]] = None):
        self.known_indicators = known_indicators or {
            "203.0.113.50": {
                "reputation": "malicious",
                "is_malicious": True,
                "asn": 64512,
                "organization": "Example C2 Network",
                "country": "XX",
                "threat_category": "Command and Control",
                "source": "MockFeed-Alpha",
                "confidence": 0.95
            }
        }

    def lookup(self, indicator: str, indicator_type: str) -> Optional[EnrichmentRecord]:
        if indicator in self.known_indicators:
            data = self.known_indicators[indicator]
            return EnrichmentRecord(
                indicator=indicator,
                indicator_type=indicator_type,
                reputation=data.get("reputation", "malicious"),
                is_malicious=data.get("is_malicious", True),
                asn=data.get("asn"),
                organization=data.get("organization"),
                country=data.get("country"),
                threat_category=data.get("threat_category"),
                source=data.get("source", "MockProvider"),
                confidence=data.get("confidence", 0.9),
                timestamp=time.time(),
                is_stale=False
            )
        return EnrichmentRecord(
            indicator=indicator,
            indicator_type=indicator_type,
            reputation="unknown",
            is_malicious=False,
            source="MockProvider",
            confidence=0.1,
            timestamp=time.time(),
            is_stale=False
        )


class FailingThreatIntelProvider(ThreatIntelProvider):
    """Simulates provider timeout or connection failure for resilience testing."""

    def lookup(self, indicator: str, indicator_type: str) -> Optional[EnrichmentRecord]:
        raise TimeoutError("External threat intelligence API timed out.")


class ThreatIntelManager:
    """Manages enrichment caching, fail-safe execution, and provider delegation."""

    def __init__(self, provider: ThreatIntelProvider, cache_ttl_seconds: int = 3600):
        self.provider = provider
        self.cache_ttl = cache_ttl_seconds
        self.cache: Dict[str, tuple[float, EnrichmentRecord]] = {}

    def enrich(self, indicator: str, indicator_type: str = "ip") -> EnrichmentRecord:
        now = time.time()
        if indicator in self.cache:
            cached_time, record = self.cache[indicator]
            if now - cached_time < self.cache_ttl:
                record.is_stale = False
                return record
            else:
                record.is_stale = True

        try:
            record = self.provider.lookup(indicator, indicator_type)
            if record:
                self.cache[indicator] = (now, record)
                return record
        except Exception:
            pass

        # Fail-safe fallback response when provider fails or times out
        return EnrichmentRecord(
            indicator=indicator,
            indicator_type=indicator_type,
            reputation="unavailable",
            is_malicious=False,
            source="Unavailable",
            confidence=0.0,
            timestamp=now,
            is_stale=True
        )