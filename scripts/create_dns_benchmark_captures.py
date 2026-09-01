#!/usr/bin/env python3
from pathlib import Path
from scapy.all import DNS, DNSQR, Ether, IP, UDP, wrpcap


def query_packet(name: str, source_port: int, timestamp: float):
    packet = Ether() / IP(src='192.168.1.10', dst='8.8.8.8') / UDP(sport=source_port, dport=53) / DNS(rd=1, qd=DNSQR(qname=name))
    packet.time = timestamp
    return packet


def main():
    root = Path('evaluation/dns_benchmark'); root.mkdir(parents=True, exist_ok=True)
    benign_names = ['www.example.com', 'api.example.com', 'cdn.example.com', 'mail.example.com']
    malicious_names = [f'{part}.exfil.invalid' for part in ['a1b2c3d4e5f6', '9f8e7d6c5b4a', '001122334455', 'abcdef012345']]
    for label, names, filename in [(0, benign_names, 'benign_dns.pcap'), (1, malicious_names, 'malicious_dns_tunneling.pcap')]:
        packets = [query_packet(name, 53000 + i, 1700001000 + i * 5) for i, name in enumerate(names)]
        wrpcap(str(root / filename), packets)
    manifest = root / 'manifest.csv'
    manifest.write_text('file,label,scenario,notes\nbenign_dns.pcap,0,benign-dns,normal short service labels\nmalicious_dns_tunneling.pcap,1,controlled-dns-tunneling,high-entropy left-most labels under reserved invalid domain\n')
    print(f'created {root / "benign_dns.pcap"}, {root / "malicious_dns_tunneling.pcap"}, and {manifest}')

if __name__ == '__main__': main()
