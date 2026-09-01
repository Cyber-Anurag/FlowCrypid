# apps/api/flow_engine.py
"""
FlowCrypid Decoupled Bidirectional Flow Engine.
Processes abstract packet events into bidirectional flow records.
"""

from dataclasses import dataclass, field
from hashlib import sha256
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class PacketEvent:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    timestamp: float
    length: int
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_flags: Optional[str] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    is_fragment: bool = False
    is_malformed: bool = False
    dns_query: str = ""


@dataclass
class FlowRecord:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    end_time: float
    duration: float = 0.0
    total_packets: int = 0
    forward_packets: int = 0
    reverse_packets: int = 0
    total_bytes: int = 0
    forward_bytes: int = 0
    reverse_bytes: int = 0
    packet_rate: float = 0.0
    byte_rate: float = 0.0
    tcp_retransmissions: int = 0
    is_malformed: bool = False
    has_fragments: bool = False
    _seen_seqs: Dict[str, set] = field(default_factory=lambda: {"fwd": set(), "rev": set()}, repr=False)

    def finalize(self) -> "FlowRecord":
        self.duration = max(0.0, self.end_time - self.start_time)
        if self.duration > 0.0:
            self.packet_rate = round(self.total_packets / self.duration, 4)
            self.byte_rate = round(self.total_bytes / self.duration, 4)
        else:
            self.packet_rate = float(self.total_packets)
            self.byte_rate = float(self.total_bytes)
        return self

    def to_dict(self) -> dict:
        return {
            "flow_id": self.flow_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "total_packets": self.total_packets,
            "forward_packets": self.forward_packets,
            "reverse_packets": self.reverse_packets,
            "total_bytes": self.total_bytes,
            "forward_bytes": self.forward_bytes,
            "reverse_bytes": self.reverse_bytes,
            "packet_rate": self.packet_rate,
            "byte_rate": self.byte_rate,
            "tcp_retransmissions": self.tcp_retransmissions,
            "is_malformed": self.is_malformed,
            "has_fragments": self.has_fragments,
        }


class FlowEngine:
    """Accumulates PacketEvents into deterministic Bidirectional FlowRecords."""

    def __init__(self, idle_timeout: float = 120.0):
        self.idle_timeout = idle_timeout
        self.active_flows: Dict[str, FlowRecord] = {}

    @staticmethod
    def compute_flow_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> Tuple[str, Tuple]:
        ep1 = (src_ip, src_port)
        ep2 = (dst_ip, dst_port)
        canonical = (ep1, ep2, proto) if ep1 <= ep2 else (ep2, ep1, proto)
        raw_key = f"{canonical[0][0]}:{canonical[0][1]}<->{canonical[1][0]}:{canonical[1][1]}:{canonical[2]}"
        flow_id = sha256(raw_key.encode("utf-8")).hexdigest()[:16]
        return flow_id, canonical

    def process_packet(self, pkt: PacketEvent) -> str:
        if pkt.is_malformed:
            flow_id, _ = self.compute_flow_key(pkt.src_ip or "0.0.0.0", pkt.dst_ip or "0.0.0.0", pkt.src_port, pkt.dst_port, pkt.protocol)
            if flow_id not in self.active_flows:
                flow = FlowRecord(
                    flow_id=flow_id,
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    src_port=pkt.src_port,
                    dst_port=pkt.dst_port,
                    protocol=pkt.protocol,
                    start_time=pkt.timestamp,
                    end_time=pkt.timestamp,
                    is_malformed=True,
                )
                self.active_flows[flow_id] = flow
            flow = self.active_flows[flow_id]
            flow.total_packets += 1
            flow.total_bytes += pkt.length
            flow.end_time = max(flow.end_time, pkt.timestamp)
            flow.is_malformed = True
            return flow_id

        # Normalize ICMP Echo request/reply into matched bidirectional flows
        s_port, d_port = pkt.src_port, pkt.dst_port
        if pkt.protocol == "ICMP" and pkt.icmp_type in (0, 8):
            s_port = 0
            d_port = 0

        flow_id, _ = self.compute_flow_key(pkt.src_ip, pkt.dst_ip, s_port, d_port, pkt.protocol)

        if flow_id not in self.active_flows:
            flow = FlowRecord(
                flow_id=flow_id,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                src_port=s_port,
                dst_port=d_port,
                protocol=pkt.protocol,
                start_time=pkt.timestamp,
                end_time=pkt.timestamp,
            )
            self.active_flows[flow_id] = flow

        flow = self.active_flows[flow_id]
        flow.end_time = max(flow.end_time, pkt.timestamp)
        flow.total_packets += 1
        flow.total_bytes += pkt.length

        if pkt.is_fragment:
            flow.has_fragments = True

        # Direction checks relative to the first packet observed
        is_fwd = (pkt.src_ip == flow.src_ip and s_port == flow.src_port)
        direction_key = "fwd" if is_fwd else "rev"

        if is_fwd:
            flow.forward_packets += 1
            flow.forward_bytes += pkt.length
        else:
            flow.reverse_packets += 1
            flow.reverse_bytes += pkt.length

        # TCP Sequence Space & Retransmission Tracking
        if pkt.protocol == "TCP" and pkt.tcp_seq is not None:
            payload_len = max(0, pkt.length - 40)  # Standard IP+TCP header size estimate
            seq_sig = (pkt.tcp_seq, payload_len)
            if payload_len > 0:
                if seq_sig in flow._seen_seqs[direction_key]:
                    flow.tcp_retransmissions += 1
                else:
                    flow._seen_seqs[direction_key].add(seq_sig)

        return flow_id

    def get_flows(self) -> List[FlowRecord]:
        return [flow.finalize() for flow in self.active_flows.values()]


def parse_pcap_stream(pcap_path: str) -> List[FlowRecord]:
    """Parses raw PCAP into FlowRecords using Scapy, falling back cleanly on malformed frames."""
    from scapy.all import DNSQR, IP, TCP, UDP, ICMP, PcapReader

    engine = FlowEngine()
    with PcapReader(pcap_path) as reader:
        for raw_pkt in reader:
            try:
                if not raw_pkt.haslayer(IP):
                    continue
                ip = raw_pkt[IP]
                proto = "OTHER"
                sport, dport = 0, 0
                seq, ack, flags = None, None, None
                icmp_type, icmp_code = None, None

                dns_query = ""
                if raw_pkt.haslayer(DNSQR):
                    try:
                        dns_query = bytes(raw_pkt[DNSQR].qname).decode("ascii", errors="ignore").rstrip(".")
                    except (AttributeError, TypeError, UnicodeError, ValueError):
                        dns_query = ""

                if raw_pkt.haslayer(TCP):

                    proto = "TCP"
                    sport = int(raw_pkt[TCP].sport)
                    dport = int(raw_pkt[TCP].dport)
                    seq = int(raw_pkt[TCP].seq)
                    ack = int(raw_pkt[TCP].ack)
                    flags = str(raw_pkt[TCP].flags)
                elif raw_pkt.haslayer(UDP):
                    proto = "UDP"
                    sport = int(raw_pkt[UDP].sport)
                    dport = int(raw_pkt[UDP].dport)
                elif raw_pkt.haslayer(ICMP):
                    proto = "ICMP"
                    icmp_type = int(raw_pkt[ICMP].type)
                    icmp_code = int(raw_pkt[ICMP].code)

                event = PacketEvent(
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=sport,
                    dst_port=dport,
                    protocol=proto,
                    timestamp=float(raw_pkt.time),
                    length=len(raw_pkt),
                    tcp_seq=seq,
                    tcp_ack=ack,
                    tcp_flags=flags,
                    icmp_type=icmp_type,
                    icmp_code=icmp_code,
                    is_fragment=bool(ip.flags & 1 or ip.frag > 0),
                    is_malformed=False,
                    dns_query=dns_query,
                )

            except Exception:
                event = PacketEvent(
                    src_ip="0.0.0.0",
                    dst_ip="0.0.0.0",
                    src_port=0,
                    dst_port=0,
                    protocol="UNKNOWN",
                    timestamp=getattr(raw_pkt, "time", 0.0),
                    length=len(raw_pkt),
                    is_malformed=True,
                )
            engine.process_packet(event)

    return engine.get_flows()