# tests/test_flow_engine.py
import pytest
from apps.api.flow_engine import FlowEngine, PacketEvent


def test_bidirectional_tcp_reconstruction():
    engine = FlowEngine()
    # Initiator: SYN
    engine.process_packet(PacketEvent("192.168.1.10", "10.0.0.1", 54321, 443, "TCP", 100.000, 64, tcp_seq=1000))
    # Responder: SYN-ACK
    engine.process_packet(PacketEvent("10.0.0.1", "192.168.1.10", 443, 54321, "TCP", 100.020, 64, tcp_seq=5000, tcp_ack=1001))
    # Initiator: ACK + Payload
    engine.process_packet(PacketEvent("192.168.1.10", "10.0.0.1", 54321, 443, "TCP", 100.030, 200, tcp_seq=1001))

    flows = engine.get_flows()
    assert len(flows) == 1
    f = flows[0]
    assert f.src_ip == "192.168.1.10"
    assert f.dst_ip == "10.0.0.1"
    assert f.forward_packets == 2
    assert f.reverse_packets == 1
    assert f.total_packets == 3
    assert f.total_bytes == 328
    assert f.duration == pytest.approx(0.030, rel=1e-3)
    assert f.tcp_retransmissions == 0


def test_tcp_retransmission_detection():
    engine = FlowEngine()
    # Segment 1
    engine.process_packet(PacketEvent("10.0.0.2", "10.0.0.3", 5000, 80, "TCP", 10.0, 100, tcp_seq=200))
    # Retransmission of Segment 1
    engine.process_packet(PacketEvent("10.0.0.2", "10.0.0.3", 5000, 80, "TCP", 10.1, 100, tcp_seq=200))

    flows = engine.get_flows()
    assert len(flows) == 1
    assert flows[0].tcp_retransmissions == 1
    assert flows[0].total_packets == 2


def test_icmp_echo_request_reply_pairing():
    engine = FlowEngine()
    # ICMP Echo Request (Type 8)
    engine.process_packet(PacketEvent("10.0.0.5", "8.8.8.8", 0, 0, "ICMP", 50.0, 84, icmp_type=8, icmp_code=0))
    # ICMP Echo Reply (Type 0)
    engine.process_packet(PacketEvent("8.8.8.8", "10.0.0.5", 0, 0, "ICMP", 50.015, 84, icmp_type=0, icmp_code=0))

    flows = engine.get_flows()
    assert len(flows) == 1
    f = flows[0]
    assert f.src_ip == "10.0.0.5"
    assert f.dst_ip == "8.8.8.8"
    assert f.forward_packets == 1
    assert f.reverse_packets == 1
    assert f.duration == pytest.approx(0.015, rel=1e-3)


def test_malformed_packet_handling():
    engine = FlowEngine()
    engine.process_packet(PacketEvent("1.1.1.1", "2.2.2.2", 80, 80, "TCP", 1.0, 50, is_malformed=True))
    flows = engine.get_flows()
    assert len(flows) == 1
    assert flows[0].is_malformed is True
    assert flows[0].total_packets == 1