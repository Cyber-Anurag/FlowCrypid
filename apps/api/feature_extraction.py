# apps/api/feature_extraction.py
"""
FlowCrypid Deterministic Feature Engineering Pipeline.
Transforms FlowRecords and PacketEvents into serializable feature vectors.
"""

import math
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any
from apps.api.flow_engine import FlowRecord, PacketEvent


@dataclass
class FlowFeatureVector:
    flow_id: str
    # Volume
    total_bytes: int
    total_packets: int
    bytes_per_packet: float
    fwd_rev_byte_ratio: float
    fwd_rev_packet_ratio: float
    # Timing
    duration: float
    packets_per_sec: float
    bytes_per_sec: float
    iat_mean: float
    iat_std: float
    iat_min: float
    iat_max: float
    # Packet Size
    packet_size_mean: float
    packet_size_std: float
    packet_size_min: int
    packet_size_max: int
    size_bin_small_ratio: float  # <128 bytes
    size_bin_medium_ratio: float # 128-1024 bytes
    size_bin_large_ratio: float  # >1024 bytes
    # Communication
    destination_port: int
    is_privileged_port: bool
    protocol_code: int
    # DNS specific
    dns_query_count: int
    dns_response_count: int
    dns_nxdomain_count: int
    dns_domain_entropy: float
    # Behavioural
    periodicity_cv: float
    burstiness_index: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def domain_label_entropy(domain: str) -> float:
    """Return Shannon entropy of the left-most DNS label using character frequencies."""
    label = (domain or "").strip().rstrip(".").split(".", 1)[0].lower()
    if not label:
        return 0.0
    frequencies: Dict[str, int] = {}
    for character in label:
        frequencies[character] = frequencies.get(character, 0) + 1
    length = len(label)
    entropy = -sum((count / length) * math.log2(count / length) for count in frequencies.values())
    return round(max(0.0, entropy), 4)


class FeatureExtractor:

    """Extracts deterministic feature vectors from flow records and packet events."""

    @staticmethod
    def _compute_stats(values: List[float]) -> tuple[float, float, float, float]:
        if not values:
            return 0.0, 0.0, 0.0, 0.0
        n = len(values)
        mean = sum(values) / n
        variance = sum((x - mean) ** 2 for x in values) / n if n > 1 else 0.0
        std = math.sqrt(variance)
        return round(mean, 4), round(std, 4), round(min(values), 4), round(max(values), 4)

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        frequencies: Dict[str, int] = {}
        for char in text:
            frequencies[char] = frequencies.get(char, 0) + 1
        for count in frequencies.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    def extract(self, flow: FlowRecord, packets: Optional[List[PacketEvent]] = None) -> FlowFeatureVector:
        packets = packets or []
        
        # 1. Volume Features
        tot_bytes = flow.total_bytes
        tot_pkts = flow.total_packets
        bytes_per_pkt = round(tot_bytes / tot_pkts, 4) if tot_pkts > 0 else 0.0
        fwd_rev_byte_rat = round(flow.forward_bytes / max(1, flow.reverse_bytes), 4)
        fwd_rev_pkt_rat = round(flow.forward_packets / max(1, flow.reverse_packets), 4)

        # 2. Timing & IAT Features
        duration = flow.duration
        pps = flow.packet_rate
        bps = flow.byte_rate

        timestamps = sorted([p.timestamp for p in packets]) if packets else []
        iats = [timestamps[i] - timestamps[i - 1] for i in range(1, len(timestamps))] if len(timestamps) > 1 else []
        iat_mean, iat_std, iat_min, iat_max = self._compute_stats(iats)

        # 3. Packet Size Features
        sizes = [p.length for p in packets] if packets else [bytes_per_pkt] if tot_pkts > 0 else [0]
        sz_mean, sz_std, sz_min, sz_max = self._compute_stats([float(s) for s in sizes])
        
        small_count = sum(1 for s in sizes if s < 128)
        med_count = sum(1 for s in sizes if 128 <= s <= 1024)
        large_count = sum(1 for s in sizes if s > 1024)
        total_sz_count = max(1, len(sizes))
        
        size_bin_small = round(small_count / total_sz_count, 4)
        size_bin_med = round(med_count / total_sz_count, 4)
        size_bin_large = round(large_count / total_sz_count, 4)

        # 4. Communication Behaviour
        proto_map = {"TCP": 6, "UDP": 17, "ICMP": 1}
        proto_code = proto_map.get(flow.protocol, 0)
        is_priv = flow.dst_port < 1024

        # 5. DNS Specific Features: query -> domain -> left-most label -> frequency distribution -> Shannon entropy.
        dns_packets = [p for p in packets if p.src_port == 53 or p.dst_port == 53]
        dns_queries = sum(1 for p in dns_packets if getattr(p, "dns_query", None)) or len(dns_packets)
        dns_responses = sum(1 for p in dns_packets if p.src_port == 53 and p.dst_port != 53)
        nxdomain_count = 0
        query_entropies = [domain_label_entropy(p.dns_query) for p in dns_packets if getattr(p, "dns_query", None)]
        domain_entropy = round(sum(query_entropies) / len(query_entropies), 4) if query_entropies else 0.0

        # 6. Behavioural Features
        periodicity_cv = round(iat_std / max(1e-6, iat_mean), 4) if iat_mean > 0 else 0.0
        burstiness_index = round(max([1.0] + [len(iats)]) / max(1.0, duration), 4)

        return FlowFeatureVector(
            flow_id=flow.flow_id,
            total_bytes=tot_bytes,
            total_packets=tot_pkts,
            bytes_per_packet=bytes_per_pkt,
            fwd_rev_byte_ratio=fwd_rev_byte_rat,
            fwd_rev_packet_ratio=fwd_rev_pkt_rat,
            duration=duration,
            packets_per_sec=pps,
            bytes_per_sec=bps,
            iat_mean=iat_mean,
            iat_std=iat_std,
            iat_min=iat_min,
            iat_max=iat_max,
            packet_size_mean=sz_mean,
            packet_size_std=sz_std,
            packet_size_min=int(sz_min),
            packet_size_max=int(sz_max),
            size_bin_small_ratio=size_bin_small,
            size_bin_medium_ratio=size_bin_med,
            size_bin_large_ratio=size_bin_large,
            destination_port=flow.dst_port,
            is_privileged_port=is_priv,
            protocol_code=proto_code,
            dns_query_count=dns_queries,
            dns_response_count=dns_responses,
            dns_nxdomain_count=nxdomain_count,
            dns_domain_entropy=domain_entropy,
            periodicity_cv=periodicity_cv,
            burstiness_index=burstiness_index,
        )