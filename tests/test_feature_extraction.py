# tests/test_feature_extraction.py
import pytest
from apps.api.flow_engine import FlowRecord, PacketEvent
from apps.api.feature_extraction import FeatureExtractor, domain_label_entropy


@pytest.fixture
def sample_flow_and_packets():
    flow = FlowRecord(
        flow_id="abc1234567890def",
        src_ip="192.168.1.50",
        dst_ip="8.8.8.8",
        src_port=49152,
        dst_port=53,
        protocol="UDP",
        start_time=1000.0,
        end_time=1001.5,
        total_packets=4,
        forward_packets=2,
        reverse_packets=2,
        total_bytes=320,
        forward_bytes=180,
        reverse_bytes=140,
    ).finalize()

    packets = [
        PacketEvent("192.168.1.50", "8.8.8.8", 49152, 53, "UDP", 1000.0, 90),
        PacketEvent("8.8.8.8", "192.168.1.50", 53, 49152, "UDP", 1000.4, 70),
        PacketEvent("192.168.1.50", "8.8.8.8", 49152, 53, "UDP", 1000.9, 90),
        PacketEvent("8.8.8.8", "192.168.1.50", 53, 49152, "UDP", 1001.5, 70),
    ]
    return flow, packets


def test_volume_feature_group(sample_flow_and_packets):
    flow, packets = sample_flow_and_packets
    extractor = FeatureExtractor()
    features = extractor.extract(flow, packets)

    assert features.total_bytes == 320
    assert features.total_packets == 4
    assert features.bytes_per_packet == 80.0
    assert features.fwd_rev_byte_ratio == 1.2857
    assert features.fwd_rev_packet_ratio == 1.0


def test_timing_and_iat_feature_group(sample_flow_and_packets):
    flow, packets = sample_flow_and_packets
    extractor = FeatureExtractor()
    features = extractor.extract(flow, packets)

    assert features.duration == 1.5
    assert features.iat_min == 0.4
    assert features.iat_max == 0.6
    assert features.iat_mean == 0.5


def test_packet_size_feature_group(sample_flow_and_packets):
    flow, packets = sample_flow_and_packets
    extractor = FeatureExtractor()
    features = extractor.extract(flow, packets)

    assert features.packet_size_min == 70
    assert features.packet_size_max == 90
    assert features.packet_size_mean == 80.0
    assert features.size_bin_small_ratio == 1.0  # all packets < 128 bytes


def test_communication_and_dns_features(sample_flow_and_packets):
    flow, packets = sample_flow_and_packets
    extractor = FeatureExtractor()
    features = extractor.extract(flow, packets)

    assert features.destination_port == 53
    assert features.is_privileged_port is True
    assert features.protocol_code == 17  # UDP
    assert features.dns_query_count == 4


def test_dns_label_entropy_is_calculated_from_character_frequencies():
    # 'aaaa' has one symbol; 'ab' has two equally likely symbols.
    assert domain_label_entropy("aaaa.example.com") == 0.0
    assert domain_label_entropy("ab.example.com") == 1.0
    assert domain_label_entropy("AB.example.com") == 1.0


def test_dns_feature_uses_actual_query_label_entropy(sample_flow_and_packets):
    flow, packets = sample_flow_and_packets
    packets[0] = PacketEvent("192.168.1.50", "8.8.8.8", 49152, 53, "UDP", 1000.0, 90, dns_query="ab.example.com")
    features = FeatureExtractor().extract(flow, packets)
    assert features.dns_domain_entropy == 1.0


def test_serialization(sample_flow_and_packets):

    flow, packets = sample_flow_and_packets
    extractor = FeatureExtractor()
    features = extractor.extract(flow, packets)
    d = features.to_dict()

    assert isinstance(d, dict)
    assert d["flow_id"] == "abc1234567890def"
    assert "total_bytes" in d
    assert "iat_mean" in d