#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient
from scapy.all import DNSQR, PcapReader


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    sample = project_root / "demo" / "sample.pcap"
    if not sample.exists():
        raise FileNotFoundError(sample)
    with tempfile.TemporaryDirectory() as directory:
        os.environ["FLOWCRYPID_DB_PATH"] = str(Path(directory) / "demo.db")
        os.environ["FLOWCRYPID_ADMIN_EMAIL"] = "demo@flowcrypid.local"
        os.environ["FLOWCRYPID_ADMIN_PASSWORD"] = "Demo-password-2026"
        from apps.api.main import app

        packet_count = 0
        dns_queries = []
        with PcapReader(str(sample)) as reader:
            for packet in reader:
                packet_count += 1
                if packet.haslayer(DNSQR):
                    dns_queries.append(bytes(packet[DNSQR].qname).decode("ascii", errors="ignore").rstrip("."))

        with TestClient(app) as client:
            login = client.post("/api/auth/login", json={"email": "demo@flowcrypid.local", "password": "Demo-password-2026"})
            login.raise_for_status()
            headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
            response = client.post("/api/upload", headers=headers, files={"file": ("sample.pcap", sample.read_bytes(), "application/vnd.tcpdump.pcap")})
            response.raise_for_status()
            submitted = response.json()
            for _ in range(100):
                job = client.get(f"/api/jobs/{submitted['id']}", headers=headers)
                job.raise_for_status()
                body = job.json()
                if body["status"] in {"completed", "failed"}:
                    break
                time.sleep(0.02)
            if body["status"] != "completed":
                raise RuntimeError(body)
            result = body["result"]
            dashboard_payload = {
                "upload": {"filename": "sample.pcap", "status_code": response.status_code, "job_id": submitted["id"]},
                "parse_packets": packet_count,
                "dns_queries": dns_queries,
                "build_flows": result["parsed_flows"],
                "extract_features": "canonical feature extraction executed for each flow",
                "run_detectors": sorted({finding["detector_id"] for finding in result["findings"]}),
                "risk_scoring": sorted({finding["risk_score"] for finding in result["findings"]}, reverse=True),
                "finding_count": len(result["findings"]),
                "findings": result["findings"],
                "dashboard_payload": result,
            }
            output = project_root / "demo" / "sample_analysis_result.json"
            output.write_text(json.dumps(dashboard_payload, indent=2) + "\n", encoding="utf-8")
            print(json.dumps(dashboard_payload, indent=2))


if __name__ == "__main__":
    main()
