#!/usr/bin/env python3
from pathlib import Path

from scapy.all import DNS, DNSQR, Ether, IP, Raw, TCP, UDP, wrpcap


def main() -> None:
    output = Path("demo/sample.pcap")
    output.parent.mkdir(parents=True, exist_ok=True)
    packets = []
    base = 1_700_000_000.0

    # A genuine DNS query whose left-most label is used by the entropy feature.
    dns = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=53000, dport=53) / DNS(rd=1, qd=DNSQR(qname="a1b2c3.example.com"))
    dns.time = base
    packets.append(dns)

    # A large, repeated TCP flow to trigger the real flow detectors and ML stage.
    for index in range(12):
        packet = Ether() / IP(src="192.168.1.10", dst="198.51.100.20") / TCP(sport=41000, dport=443, seq=index * 60000, flags="PA") / Raw(load=b"F" * 60000)
        packet.time = base + 1.0 + index * 0.5
        packets.append(packet)

    wrpcap(str(output), packets)
    print(f"wrote {output} ({len(packets)} packets, {output.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
