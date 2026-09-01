# apps/api/detector_engine.py
"""
Refactored Behavioral Detection Engine.
Produces structured, machine-readable evidence separating observation, anomaly, severity, and confidence.
"""

from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional
from apps.api.flow_engine import FlowRecord, PacketEvent
from apps.api.feature_extraction import FlowFeatureVector, FeatureExtractor
from apps.api.detector_config import DetectorConfig


@dataclass
class DetectionFinding:
    detector_id: str
    severity: str        # 'low', 'medium', 'high'
    confidence: float    # 0.0 to 1.0
    features: Dict[str, Any]
    thresholds: Dict[str, Any]
    evidence: Dict[str, Any]
    explanation: str

    to_dict = lambda self: asdict(self)


class BehavioralDetectorEngine:
    """Executes deterministic, rule-based behavioral anomaly detection."""

    def __init__(self, config: DetectorConfig = DetectorConfig()):
        self.config = config
        self.extractor = FeatureExtractor()

    @staticmethod
    def _is_external_ip(ip: str) -> bool:
        if not ip or ip.startswith(("10.", "192.168.", "127.", "0.")):
            return False
        if ip.startswith("172."):
            try:
                second_octet = int(ip.split(".")[1])
                if 16 <= second_octet <= 31:
                    return False
            except (IndexError, ValueError):
                pass
        return True

    def analyze_flow(self, flow: FlowRecord, packets: Optional[List[PacketEvent]] = None) -> List[DetectionFinding]:
        findings: List[DetectionFinding] = []
        features = self.extractor.extract(flow, packets)
        pkts = packets or []

        # A. Large external transfer (DET-VOL-001)
        if flow.total_bytes > self.config.LARGE_TRANSFER_BYTES and self._is_external_ip(flow.dst_ip):
            findings.append(DetectionFinding(
                detector_id="DET-VOL-001",
                severity="medium",
                confidence=0.85,
                features={"total_bytes": flow.total_bytes, "dst_ip": flow.dst_ip},
                thresholds={"large_transfer_bytes": self.config.LARGE_TRANSFER_BYTES},
                evidence={"transfer_volume": flow.total_bytes, "direction": "outbound_external"},
                explanation=f"Flow transferred {flow.total_bytes:,} bytes to external IP {flow.dst_ip}, exceeding standard volume thresholds."
            ))

        # B. Unusual outbound/inbound byte asymmetry (DET-VOL-002)
        if features.fwd_rev_byte_ratio >= self.config.ASYMMETRY_RATIO_MIN and flow.total_bytes > 10240:
            findings.append(DetectionFinding(
                detector_id="DET-VOL-002",
                severity="medium",
                confidence=0.80,
                features={"fwd_rev_byte_ratio": features.fwd_rev_byte_ratio, "forward_bytes": flow.forward_bytes, "reverse_bytes": flow.reverse_bytes},
                thresholds={"asymmetry_ratio_min": self.config.ASYMMETRY_RATIO_MIN},
                evidence={"forward_bytes": flow.forward_bytes, "reverse_bytes": flow.reverse_bytes, "ratio": features.fwd_rev_byte_ratio},
                explanation=f"Observed high volume asymmetry (ratio: {features.fwd_rev_byte_ratio:.2f}) with heavy outbound data and minimal response."
            ))

        # C. Beaconing / periodic communication (DET-BEH-001)
        if flow.total_packets >= self.config.MIN_BEACON_PACKETS and features.periodicity_cv <= self.config.BEACONING_CV_MAX and features.iat_mean > 0:
            findings.append(DetectionFinding(
                detector_id="DET-BEH-001",
                severity="high",
                confidence=0.75,
                features={"periodicity_cv": features.periodicity_cv, "total_packets": flow.total_packets, "iat_mean": features.iat_mean},
                thresholds={"periodicity_cv_max": self.config.BEACONING_CV_MAX},
                evidence={"inter_arrival_time_cv": features.periodicity_cv, "mean_iat": features.iat_mean},
                explanation=f"Flow exhibits low timing jitter (CV: {features.periodicity_cv:.3f}) across {flow.total_packets} packets, indicative of automated periodic beaconing."
            ))

        # D. Suspicious DNS behaviour (DET-DNS-001)
        if features.dns_query_count > 0 and (features.dns_domain_entropy >= self.config.DNS_ENTROPY_MIN or features.dns_nxdomain_count >= self.config.DNS_NXDOMAIN_MIN):
            findings.append(DetectionFinding(
                detector_id="DET-DNS-001",
                severity="medium",
                confidence=0.85,
                features={"dns_domain_entropy": features.dns_domain_entropy, "dns_nxdomain_count": features.dns_nxdomain_count},
                thresholds={"dns_entropy_min": self.config.DNS_ENTROPY_MIN, "dns_nxdomain_min": self.config.DNS_NXDOMAIN_MIN},
                evidence={"entropy": features.dns_domain_entropy, "nxdomain_count": features.dns_nxdomain_count},
                explanation=f"DNS query characteristics show elevated entropy ({features.dns_domain_entropy:.2f}) or NXDOMAIN frequency, consistent with domain generation algorithms (DGA)."
            ))

        # E. High-frequency connection behaviour (DET-NET-001)
        if flow.packet_rate >= self.config.PACKET_RATE_MAX:
            findings.append(DetectionFinding(
                detector_id="DET-NET-001",
                severity="low",
                confidence=0.70,
                features={"packet_rate": flow.packet_rate},
                thresholds={"packet_rate_max": self.config.PACKET_RATE_MAX},
                evidence={"observed_packet_rate": flow.packet_rate},
                explanation=f"Flow packet rate ({flow.packet_rate:.1f} pps) exceeds baseline throughput thresholds."
            ))

        # G. Potential data exfiltration patterns (DET-EXF-001)
        if flow.total_bytes > self.config.LARGE_TRANSFER_BYTES and features.fwd_rev_byte_ratio >= self.config.ASYMMETRY_RATIO_MIN and self._is_external_ip(flow.dst_ip):
            findings.append(DetectionFinding(
                detector_id="DET-EXF-001",
                severity="high",
                confidence=0.90,
                features={"total_bytes": flow.total_bytes, "fwd_rev_byte_ratio": features.fwd_rev_byte_ratio},
                thresholds={"large_transfer_bytes": self.config.LARGE_TRANSFER_BYTES, "asymmetry_min": self.config.ASYMMETRY_RATIO_MIN},
                evidence={"volume": flow.total_bytes, "ratio": features.fwd_rev_byte_ratio, "destination": flow.dst_ip},
                explanation=f"Combined anomaly indicator: Large external data transfer ({flow.total_bytes:,} bytes) coupled with high outbound asymmetry matches potential exfiltration patterns."
            ))

        return findings