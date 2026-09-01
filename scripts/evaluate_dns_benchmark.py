#!/usr/bin/env python3
from pathlib import Path
import json
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scapy.all import DNSQR, PcapReader
from apps.api.feature_extraction import domain_label_entropy

def main():
    root=Path(__file__).resolve().parents[1]; out={}
    for label,name in [(0,'benign_dns.pcap'),(1,'malicious_dns_tunneling.pcap')]:
        values=[]; queries=[]
        with PcapReader(str(root/'evaluation/dns_benchmark'/name)) as reader:
            for packet in reader:
                if packet.haslayer(DNSQR):
                    query=bytes(packet[DNSQR].qname).decode('ascii','ignore').rstrip('.')
                    queries.append(query); values.append(domain_label_entropy(query))
        out[name]={'label':label,'queries':queries,'entropy_bits':values,'mean_entropy_bits':sum(values)/len(values)}
    out['measured_separation_bits']=out['malicious_dns_tunneling.pcap']['mean_entropy_bits']-out['benign_dns.pcap']['mean_entropy_bits']
    path=root/'evaluation/results/dns_benchmark.json'; path.write_text(json.dumps(out,indent=2)+'\n'); print(json.dumps(out,indent=2))
if __name__=='__main__': main()
