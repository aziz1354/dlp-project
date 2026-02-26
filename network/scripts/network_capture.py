#!/usr/bin/env python3
from scapy.all import sniff, TCP, UDP, IP
from feature_extractor import FeatureExtractor
import threading
import time
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class NetworkDLPCapture:
    def __init__(self):
        self.interface = "ens33"  # Change to your interface
        self.extractor = FeatureExtractor()
        self.capture_running = False
        self.processed_dir = Path("/root/dlp_project/processed_features")
        self.processed_dir.mkdir(exist_ok=True)

    def packet_handler(self, packet):
        """Process individual packets"""
        if IP in packet:
            # Extract basic flow info
            flow_key = (packet[IP].src, packet[IP].dst, 
                       packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else 0,
                       packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else 0)

            # Add your custom processing here
            features = {
                'timestamp': time.time(),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': 'TCP' if TCP in packet else 'UDP' if UDP in packet else 'Other',
                'length': len(packet)
            }
            
            # Save features (in production, buffer and batch process)
            output_file = self.processed_dir / f"packet_{time.time()}.json"
            with open(output_file, 'w') as f:
                f.write(str(features))

    def start_capture(self):
        """Start the packet capture"""
        self.capture_running = True
        logger.info(f"Starting DLP capture on {self.interface}")
        sniff(iface=self.interface, 
              prn=self.packet_handler,
              store=False,
              stop_filter=lambda x: not self.capture_running)

if __name__ == "__main__":
    capture = NetworkDLPCapture()
    try:
        capture.start_capture()
    except KeyboardInterrupt:
        capture.capture_running = False
