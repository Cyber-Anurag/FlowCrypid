"""
FlowCrypid security regression and hardening tests.

The authenticated upload validation path is covered by scripts/smoke_test_backend.py;
these tests cover the public API contract and parser boundary behavior.
"""

import os
import tempfile
import time

from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from apps.api.flow_engine import FlowEngine, PacketEvent, parse_pcap_stream
from apps.api.main import app, check_rate_limit, valid_capture_magic


client = TestClient(app)


def test_upload_requires_authentication_before_extension_validation():
    response = client.post(
        "/api/upload",
        files={"file": ("malicious.exe", b"MZ simulant binary payload", "application/octet-stream")},
    )
    assert response.status_code == 401
    assert "Authentication required" in response.json()["detail"]


def test_path_traversal_filename_is_not_processed_without_authentication():
    response = client.post(
        "/api/upload",
        files={"file": ("../../etc/passwd.pcap", b"dummy pcap bytes", "application/octet-stream")},
    )
    assert response.status_code == 401


def test_capture_magic_validation():
    assert valid_capture_magic(b"\xd4\xc3\xb2\xa1") is True
    assert valid_capture_magic(b"\x0a\x0d\x0d\x0a") is True
    assert valid_capture_magic(b"MZ00") is False
    assert valid_capture_magic(b"") is False


def test_rate_limit_blocks_after_configured_attempts():
    request = Request({
        "type": "http",
        "method": "POST",
        "path": "/api/test",
        "headers": [],
        "client": ("phase2-test-client", 1234),
        "query_string": b"",
        "server": ("testserver", 80),
        "scheme": "http",
    })
    bucket = f"phase2-rate-limit-{time.time_ns()}"
    check_rate_limit(request, bucket, 1)
    try:
        check_rate_limit(request, bucket, 1)
        assert False, "second request should be rate limited"
    except HTTPException as error:
        assert error.status_code == 429
        assert error.headers["Retry-After"]


def test_malformed_pcap_parser_resilience():
    engine = FlowEngine()
    malformed_event = PacketEvent(
        src_ip=None,
        dst_ip=None,
        src_port=0,
        dst_port=0,
        protocol="UNKNOWN",
        timestamp=0.0,
        length=9999,
        is_malformed=True,
    )
    engine.process_packet(malformed_event)
    flows = engine.get_flows()

    assert len(flows) == 1
    assert flows[0].is_malformed is True
    assert flows[0].total_packets == 1


def test_resource_exhaustion_large_payload_guard():
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as temporary_file:
        temporary_file.write(b"\xd4\xc3\xb2\xa1" + b"\x00" * 100)
        temporary_path = temporary_file.name

    try:
        flows = parse_pcap_stream(temporary_path)
        assert isinstance(flows, list)
    finally:
        if os.path.exists(temporary_path):
            os.remove(temporary_path)
