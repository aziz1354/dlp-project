#!/usr/bin/env python3
import json
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR
from pathlib import Path
import time
import logging
from typing import Dict, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FeatureExtractor:
    def __init__(self):
        self.output_dir = Path("/root/dlp_project/processed_features")
        self.output_dir.mkdir(exist_ok=True)
        
    def _convert_to_serializable(self, obj):
        if isinstance(obj, (np.integer, np.floating)):
            return int(obj) if isinstance(obj, np.integer) else float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return obj

    def extract_pcap_features(self, pcap_path):
        try:
            packets = rdpcap(str(pcap_path))
            
            # Enhanced feature extraction
            features: Dict[str, Any] = {
                "timestamp": time.time(),
                "total_packets": len(packets),
                "protocol_dist": {
                    "TCP": sum(1 for p in packets if TCP in p),
                    "UDP": sum(1 for p in packets if UDP in p),
                    "ICMP": sum(1 for p in packets if IP in p and p[IP].proto == 1)
                }
            }
            
            # Try to extract more specific network details
            dns_packets = [p for p in packets if DNS in p]
            if dns_packets:
                # DNS-specific features
                features["dns_queries"] = len(dns_packets)
                features["dns_tunneling_indicators"] = sum(
                    1 for p in dns_packets 
                    if len(p[DNS].qd.qname.decode('ascii', 'ignore')) > 100
                )
            
            # Convert numpy types and ensure JSON serializability
            features = {k: self._convert_to_serializable(v) for k,v in features.items()}
            
            # Generate output filename with timestamp
            output_file = self.output_dir / f"packet_{time.time()}.json"
            
            # Ensure valid JSON formatting
            with open(output_file, 'w') as f:
                json.dump(features, f, indent=2)
            
            logger.info(f"Features extracted and saved to {output_file}")
            return str(output_file)
        
        except Exception as e:
            logger.error(f"Error processing {pcap_path}: {str(e)}")
            return None

def main():
    import sys
    if len(sys.argv) != 2:
        print("Usage: python feature_extractor.py <pcap_file>")
        sys.exit(1)
        
    extractor = FeatureExtractor()
    result = extractor.extract_pcap_features(Path(sys.argv[1]))
    if result:
        print(f"Features extracted and saved to {result}")

if __name__ == "__main__":
    main()
