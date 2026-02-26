#!/usr/bin/env python3
from scapy.all import *
import random
import time

def generate_sample_pcap(output_path='/tmp/test_traffic.pcap', packet_count=100):
    """
    Generate a sample PCAP file with diverse network traffic
    
    Args:
        output_path (str): Path to save the generated PCAP
        packet_count (int): Number of packets to generate
    """
    packets = []
    
    # Generate TCP packets
    for _ in range(packet_count // 3):
        # HTTP-like traffic
        src_ip = f"192.168.1.{random.randint(1, 254)}"
        dst_ip = f"10.0.0.{random.randint(1, 254)}"
        
        # Create TCP packet simulating HTTP traffic
        tcp_packet = IP(src=src_ip, dst=dst_ip)/\
                     TCP(sport=random.randint(1024, 65535), 
                         dport=random.choice([80, 443]), 
                         flags="PA")/\
                     Raw(load=f"GET /sample{random.randint(1,100)}.html HTTP/1.1\r\nHost: example.com\r\n\r\n")
        
        packets.append(tcp_packet)
    
    # Generate UDP packets (DNS-like)
    for _ in range(packet_count // 3):
        src_ip = f"192.168.1.{random.randint(1, 254)}"
        dst_ip = f"8.8.{random.randint(1, 8)}.{random.randint(1, 8)}"
        
        # Create DNS-like query packet
        dns_packet = IP(src=src_ip, dst=dst_ip)/\
                     UDP(sport=random.randint(1024, 65535), dport=53)/\
                     DNS(rd=1, qd=DNSQR(qname=f"test{random.randint(1,100)}.com"))
        
        packets.append(dns_packet)
    
    # Generate ICMP packets
    for _ in range(packet_count // 3):
        src_ip = f"10.0.0.{random.randint(1, 254)}"
        dst_ip = f"192.168.1.{random.randint(1, 254)}"
        
        # Create ICMP ping packet
        icmp_packet = IP(src=src_ip, dst=dst_ip)/ICMP()
        
        packets.append(icmp_packet)
    
    # Write packets to PCAP
    wrpcap(output_path, packets)
    print(f"Generated test PCAP at {output_path} with {len(packets)} packets")
    
    return output_path

if __name__ == "__main__":
    generate_sample_pcap()
