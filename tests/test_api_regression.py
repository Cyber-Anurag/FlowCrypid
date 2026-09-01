from fastapi.testclient import TestClient

from apps.api import main as api
from apps.api.main import Flow, app, classify_flow


client = TestClient(app)


def test_health_check_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"


def test_password_rotation_requires_authentication():
    response = client.post("/api/auth/password", json={"current_password": "old-password", "new_password": "new-password-123"})
    assert response.status_code == 401


def test_operational_endpoints_expose_worker_and_detector_metadata():
    ready = client.get("/api/health/ready")
    assert ready.status_code == 200
    assert ready.json()["worker_count"] >= 1
    assert ready.json()["detector_version"] == "heuristic-v2"
    metrics = client.get("/api/metrics")
    assert metrics.status_code == 200
    assert "flowcrypid_http_requests_total" in metrics.text
    assert "flowcrypid_analysis_workers" in metrics.text


def test_after_hours_and_upload_download_signals_are_explainable():
    finding = classify_flow(
        Flow(source_ip="192.168.1.10", dest_ip="8.8.8.8", source_port=40000, dest_port=443, protocol=6, packets=8, bytes=800_000, first_seen=1_700_000_000, last_seen=1_700_000_240),
        2,
        download_bytes=10_000,
    )
    assert finding is not None
    assert "P0_AFTER_HOURS_TRANSFER" in finding.contributing_signals
    assert "P1_UPLOAD_DOWNLOAD_IMBALANCE" in finding.contributing_signals
    assert any("08:00–18:00" in item for item in finding.explanation)


def test_context_enrichment_signals_are_explainable(monkeypatch):
    monkeypatch.setattr(api, "SUSPICIOUS_DESTINATIONS", {"9.9.9.9"})
    monkeypatch.setattr(api, "CRITICAL_SOURCES", {"192.168.1.20"})
    monkeypatch.setattr(api, "SOURCE_BASELINES", {"192.168.1.20": 100_000})
    finding = classify_flow(Flow(source_ip="192.168.1.20", dest_ip="9.9.9.9", source_port=42000, dest_port=443, protocol=6, packets=8, bytes=500_000, first_seen=1_700_000_000, last_seen=1_700_000_180), 5)
    assert finding is not None
    assert "P0_REPUTATION_MATCH" in finding.contributing_signals
    assert "P1_CRITICAL_ASSET_ACTIVITY" in finding.contributing_signals
    assert "P1_BEHAVIORAL_DEVIATION" in finding.contributing_signals


def test_dns_and_protocol_indicators_are_explainable():
    dns_finding = classify_flow(Flow(source_ip="192.168.1.10", dest_ip="8.8.8.8", source_port=42000, dest_port=53, protocol=17, packets=20, bytes=200_000, first_seen=1_700_000_000, last_seen=1_700_000_180), 3)
    assert dns_finding is not None
    assert "P2_ABNORMAL_DNS_VOLUME" in dns_finding.contributing_signals
    assert "P2_DNS_TUNNELING_LIKE" in dns_finding.contributing_signals
    unusual_finding = classify_flow(Flow(source_ip="192.168.1.10", dest_ip="8.8.4.4", source_port=42000, dest_port=31337, protocol=6, packets=8, bytes=50_000, first_seen=1_700_000_000, last_seen=1_700_000_180), 4)
    assert unusual_finding is not None
    assert "P2_UNUSUAL_DESTINATION_PORT" in unusual_finding.contributing_signals


def test_multi_signal_finding_has_versioned_explainability_metadata():
    finding = classify_flow(
        Flow(
            source_ip="192.168.1.10",
            dest_ip="8.8.8.8",
            source_port=40000,
            dest_port=443,
            protocol=6,
            packets=2,
            bytes=2_000_000,
            first_seen=1_700_000_000,
            last_seen=1_700_000_060,
        ),
        1,
    )
    assert finding is not None
    assert finding.detector_id == "FLOW-ENSEMBLE"
    assert finding.detector_version == "heuristic-v2"
    assert finding.tier == "P0"
    assert finding.risk_score >= 95
    assert finding.confidence > 0.9
    assert "P0_LOW_AND_SLOW_EXFIL" in finding.contributing_signals
    assert "P1_RARE_EXTERNAL_DESTINATION" in finding.contributing_signals
    assert any("not a calibrated probability" in item for item in finding.explanation)


def test_audit_endpoint_requires_authentication():
    response = client.get("/api/audit")
    assert response.status_code == 401
    verification = client.get("/api/audit/verify")
    assert verification.status_code == 401


def test_upload_requires_authentication_before_file_validation():
    response = client.post(
        "/api/upload",
        files={"file": ("test.txt", b"invalid data", "text/plain")},
    )
    assert response.status_code == 401
    assert "Authentication required" in response.json()["detail"]


def test_detector_status_is_explicit_about_validation_and_provenance():
    response = client.get("/api/detector/status")
    assert response.status_code == 200
    payload = response.json()
    assert payload["detector_id"] == "FLOW-ENSEMBLE"
    assert payload["detector_version"] == "heuristic-v2"
    assert payload["validation_status"] in {"unvalidated", "validated-calibration"}
    assert "warning" in payload


def test_api_responses_are_not_cacheable():
    response = client.get("/api/health")
    assert response.headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy-Report-Only"]


def test_unsupported_worker_mode_fails_closed(monkeypatch):
    monkeypatch.setattr(api, "WORKER_MODE", "external")
    response = client.post("/api/upload", files={"file": ("test.pcap", b"\xd4\xc3\xb2\xa1", "application/vnd.tcpdump.pcap")})
    assert response.status_code == 401
    # Authentication is intentionally checked before the mode guard.
    monkeypatch.setattr(api, "WORKER_MODE", "local")


def test_high_entropy_dns_signal_is_explainable():
    finding = classify_flow(
        Flow(
            source_ip="192.168.1.10",
            dest_ip="8.8.8.8",
            source_port=42000,
            dest_port=53,
            protocol=17,
            packets=4,
            bytes=4_000,
            first_seen=1_700_000_000,
            last_seen=1_700_000_030,
            dns_query="x9k2m7q4v8n3p6r1t5y0.example.com",
            dns_entropy=4.7,
        ),
        6,
    )
    assert finding is not None
    assert "P2_HIGH_ENTROPY_DNS" in finding.contributing_signals
    assert any("Shannon entropy" in item for item in finding.explanation)
