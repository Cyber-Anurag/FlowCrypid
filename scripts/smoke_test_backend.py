from pathlib import Path
import os
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient
from scapy.all import Ether, IP, TCP, wrpcap

with tempfile.TemporaryDirectory() as directory:
    os.environ["FLOWCRYPID_DB_PATH"] = str(Path(directory) / "test.db")
    os.environ["FLOWCRYPID_ADMIN_EMAIL"] = "admin@test.local"
    os.environ["FLOWCRYPID_ADMIN_PASSWORD"] = "Test-password-2026"
    from apps.api.main import app

    capture = Path(directory) / "fixture.pcap"
    packets = []
    for index in range(8):
        packet = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=40000 + index, dport=443)
        packet.time = 1_700_000_000 + index * 60
        packets.append(packet)
    wrpcap(str(capture), packets)

    client = TestClient(app)
    health = client.get("/api/health")
    assert health.status_code == 200, health.text
    assert health.json()["components"]["baseline_store"] == "sqlite"

    unauthorized = client.post("/api/upload", files={"file": ("fixture.pcap", capture.read_bytes(), "application/vnd.tcpdump.pcap")})
    assert unauthorized.status_code == 401, unauthorized.text

    login = client.post("/api/auth/login", json={"email": "admin@test.local", "password": "Test-password-2026"})
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/auth/me", headers=headers).json()["role"] == "admin"

    response = client.post("/api/upload", headers=headers, files={"file": ("fixture.pcap", capture.read_bytes(), "application/vnd.tcpdump.pcap")})
    assert response.status_code == 202, response.text
    submitted = response.json()
    assert submitted["id"].startswith("JOB-")
    assert submitted["status"] in {"queued", "processing", "completed"}
    body = None
    for _ in range(40):
        job = client.get(f"/api/jobs/{submitted['id']}", headers=headers)
        assert job.status_code == 200, job.text
        body = job.json()
        if body["status"] in {"completed", "failed"}:
            break
        time.sleep(0.025)
    assert body["status"] == "completed", body
    result = body["result"]
    assert result["capture_id"].startswith("CAP-")
    assert result["total_packets"] == 8
    assert result["parsed_flows"] == 8
    assert "findings" in result

    history = client.get("/api/captures", headers=headers)
    assert history.status_code == 200, history.text
    assert history.json()[0]["id"] == result["capture_id"]

    invalid = client.post("/api/upload", headers=headers, files={"file": ("notes.txt", b"not a capture", "text/plain")})
    assert invalid.status_code == 415, invalid.text

    assert client.post("/api/auth/logout", headers=headers).status_code == 200
    assert client.get("/api/auth/me", headers=headers).status_code == 401

print("secure backend smoke test passed")
