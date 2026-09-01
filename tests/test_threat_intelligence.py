# tests/test_threat_intelligence.py
import pytest
from apps.api.threat_intelligence import ThreatIntelManager, MockThreatIntelProvider, FailingThreatIntelProvider


def test_mock_provider_malicious_lookup():
    provider = MockThreatIntelProvider()
    manager = ThreatIntelManager(provider)

    record = manager.enrich("203.0.113.50", "ip")
    assert record.reputation == "malicious"
    assert record.is_malicious is True
    assert record.source == "MockFeed-Alpha"
    assert record.is_stale is False


def test_graceful_failure_and_fallback():
    provider = FailingThreatIntelProvider()
    manager = ThreatIntelManager(provider)

    record = manager.enrich("192.0.2.1", "ip")
    assert record.reputation == "unavailable"
    assert record.is_malicious is False
    assert record.is_stale is True
    assert record.source == "Unavailable"


def test_caching_behavior():
    provider = MockThreatIntelProvider()
    manager = ThreatIntelManager(provider, cache_ttl_seconds=60)

    rec1 = manager.enrich("203.0.113.50", "ip")
    rec2 = manager.enrich("203.0.113.50", "ip")
    assert rec1.timestamp == rec2.timestamp