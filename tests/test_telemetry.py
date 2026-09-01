from datetime import datetime, timezone

from apps.api.correlation import correlate_events
from apps.api.telemetry import DNSEvent, FileAccessEvent, NetworkFlowEvent, normalize_event


def test_normalize_network_event_is_stable_json_shape():
    event = NetworkFlowEvent(
        event_id="evt-net-001",
        observed_at=datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc),
        source_ip="192.168.1.10",
        destination_ip="8.8.8.8",
        destination_port=443,
        bytes_out=1000,
    )
    normalized = normalize_event(event)
    assert normalized["event_type"] == "network_flow"
    assert normalized["observed_at"] == "2026-08-31T12:00:00+00:00"
    assert normalized["bytes_out"] == 1000


def test_correlate_sensitive_access_dns_and_external_transfer():
    events = [
        FileAccessEvent(event_id="evt-file-001", observed_at=datetime(2026, 8, 31, 12, 0, tzinfo=timezone.utc), source_ip="192.168.1.10", action="read", sensitivity="critical", bytes_accessed=2_000_000),
        DNSEvent(event_id="evt-dns-001", observed_at=datetime(2026, 8, 31, 12, 1, tzinfo=timezone.utc), source_ip="192.168.1.10", query="example.test"),
        NetworkFlowEvent(event_id="evt-flow-001", observed_at=datetime(2026, 8, 31, 12, 2, tzinfo=timezone.utc), source_ip="192.168.1.10", destination_ip="8.8.8.8", destination_port=443, bytes_out=1_000_000),
    ]
    chains = correlate_events([normalize_event(event) for event in events])
    ids = {chain["chain_id"] for chain in chains}
    assert "CHAIN-SENSITIVE-EXFIL" in ids
    assert "CHAIN-DNS-HTTPS" in ids
