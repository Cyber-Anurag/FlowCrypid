# tests/test_detectors.py
import pytest
from apps.api.flow_engine import FlowRecord, PacketEvent
from apps.api.detector_engine import BehavioralDetectorEngine
from apps.api.detector_config import DetectorConfig


def test_large_external_transfer_detector():
    engine = BehavioralDetectorEngine()
    flow = FlowRecord(
        flow_id="test001",
        src_ip="192.168.1.10",
        dst_ip="203.0.113.50",  # External IP
        src_port=54321,
        dst_port=443,
        protocol="TCP",
        start_time=1000.0,
        end_time=1010.0,
        total_packets=1000,
        forward_packets=900,
        reverse_packets=100,
        total_bytes=60 * 1024 * 1024,  # 60 MB
        forward_bytes=59 * 1024 * 1024,
        reverse_bytes=1 * 1024 * 1024,
    ).finalize()

    findings = engine.analyze_flow(flow)
    finding_ids = [f.detector_id for f in findings]
    assert "DET-VOL-001" in finding_ids
    assert "DET-EXF-001" in finding_ids


def test_benign_traffic_no_findings():
    engine = BehavioralDetectorEngine()
    flow = FlowRecord(
        flow_id="test002",
        src_ip="192.168.1.10",
        dst_ip="192.168.1.1",
        src_port=54321,
        dst_port=53,
        protocol="UDP",
        start_time=1000.0,
        end_time=1000.5,
        total_packets=2,
        forward_packets=1,
        reverse_packets=1,
        total_bytes=150,
        forward_bytes=80,
        reverse_bytes=70,
    ).finalize()

    findings = engine.analyze_flow(flow)
    assert len(findings) == 0


def test_missing_data_boundary_conditions():
    engine = BehavioralDetectorEngine()
    # Zero duration and zero packet edge case
    flow = FlowRecord(
        flow_id="test003",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1234,
        dst_port=80,
        protocol="TCP",
        start_time=0.0,
        end_time=0.0,
        total_packets=0,
        forward_packets=0,
        reverse_packets=0,
        total_bytes=0,
    ).finalize()

    findings = engine.analyze_flow(flow, packets=[])
    assert isinstance(findings, list)
    assert len(findings) == 0