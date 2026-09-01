from pathlib import Path
import tempfile

from scapy.all import IP, TCP, Raw, wrpcap

from apps.api.main import ML_MODEL, _flow_features, analyze_capture
from apps.api.flow_engine import parse_pcap_stream


def main() -> None:
    if ML_MODEL.status != "ready":
        raise RuntimeError("startup detector did not load persisted artifacts")
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "verification.pcap"
        packets = [
            IP(src="10.0.0.10", dst="198.51.100.10") / TCP(sport=40000 + i, dport=443, flags="PA") / Raw(load=b"x" * (1500 + i * 250))
            for i in range(12)
        ]
        for i, packet in enumerate(packets):
            packet.time = 1700000000.0 + i * 0.25
        wrpcap(str(path), packets)
        flows = parse_pcap_stream(str(path))
        if not flows:
            raise RuntimeError("PCAP parser returned no flows")
        feature = _flow_features(type("Flow", (), {
            "source_ip": flows[0].src_ip, "dest_ip": flows[0].dst_ip,
            "source_port": flows[0].src_port, "dest_port": flows[0].dst_port,
            "protocol": 6, "packets": flows[0].total_packets, "bytes": flows[0].total_bytes,
            "first_seen": flows[0].start_time, "last_seen": flows[0].end_time,
            "dns_query": "", "dns_entropy": 0.0,
        })(), 1)
        score = ML_MODEL.analyze(feature)
        result = analyze_capture(path)
        print({"flows": len(flows), "feature_count": len(feature.to_dict()), "model_status": ML_MODEL.status, "normalized_score": score.normalized_score, "findings": len(result.findings)})


if __name__ == "__main__":
    main()
