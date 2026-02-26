#!/usr/bin/env python3
from scapy.all import *
import base64
import random
import string

def generate_suspicious_dns_query():
    """Generate a highly suspicious DNS query that mimics tunneling"""
    # Techniques to simulate DNS tunneling
    techniques = [
        # Long base64-like subdomain
        lambda: ''.join(random.choices(string.ascii_letters + string.digits + '=', k=random.randint(100, 250))) + ".tunnel.example.com",
        
        # Encoded data-like subdomain
        lambda: base64.b64encode(f"secret_data_{random.randint(1000, 9999)}".encode()).decode().replace('=', 'x') + ".exfil.example.com",
        
        # High-entropy domain
        lambda: ''.join(random.choices(string.ascii_letters + string.digits, k=random.randint(100, 200))) + ".entropy.example.com"
    ]
    
    return random.choice(techniques)()

def create_dns_tunneling_pcap(output_file='/root/dlp_project/test_dns_tunneling.pcap', num_packets=50):
    """
    Create a PCAP file simulating DNS tunneling
    
    Args:
        output_file (str): Path to save the PCAP
        num_packets (int): Number of packets to generate
    """
    packets = []
    
    for i in range(num_packets):
        # Mix of normal and suspicious DNS queries
        if i % 5 == 0:
            # Normal DNS query
            dns_query = f"normal-query-{i}.example.com"
        else:
            # Suspicious DNS query mimicking tunneling
            dns_query = generate_suspicious_dns_query()
        
        # Construct DNS packet
        ip_packet = IP(src="192.168.1.100", dst="8.8.8.8")
        udp_packet = UDP(sport=random.randint(1024, 65535), dport=53)
        dns_packet = DNS(
            rd=1,  # Recursion desired
            qd=DNSQR(qname=dns_query)
        )
        
        # Combine layers
        full_packet = ip_packet/udp_packet/dns_packet
        packets.append(full_packet)
    
    # Write to PCAP
    wrpcap(output_file, packets)
    print(f"Generated test PCAP: {output_file}")
    print(f"Total packets: {len(packets)}")
    
    # Count suspicious queries
    suspicious_queries = sum(1 for p in packets 
                             if len(p[DNS].qd.qname) > 100 or 
                             '.' in p[DNS].qd.qname and len(p[DNS].qd.qname.split('.')[0]) > 100)
    print(f"Suspicious DNS queries: {suspicious_queries}")

def main():
    create_dns_tunneling_pcap()

if __name__ == "__main__":
    main()
