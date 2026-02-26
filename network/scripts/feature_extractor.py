#!/usr/bin/env python3
import json
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP, DNS
from pathlib import Path
import time
import logging
import re
from typing import Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='/var/log/dlp/feature_extractor.log',
    filemode='a'
)
logger = logging.getLogger(__name__)

class FeatureExtractor:
    def __init__(self):
        self.output_dir = Path("/root/dlp_project/processed_features")
        self.output_dir.mkdir(exist_ok=True)
        
        # Tunneling detection parameters
        self.dns_tunneling_thresholds = {
            'max_domain_length': 100,  # Suspiciously long domain
            'entropy_threshold': 3.5,  # High entropy suggests encoded data
            'base64_ratio': 0.7,  # High ratio of base64-like characters
        }
    
    def _calculate_entropy(self, domain: str) -> float:
        """Calculate Shannon entropy of a domain"""
        import math
        
        # Count character frequencies
        freq = {}
        for char in domain:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        for count in freq.values():
            prob = count / len(domain)
            entropy -= prob * math.log2(prob)
        
        return entropy
    
    def _is_potential_dns_tunneling(self, domain: str) -> bool:
        """
        Detect potential DNS tunneling indicators
        
        Args:
            domain (str): DNS query domain
        
        Returns:
            bool: True if domain looks suspicious
        """
        try:
            # Check domain length
            if len(domain) > self.dns_tunneling_thresholds['max_domain_length']:
                return True
            
            # Check entropy (randomness)
            entropy = self._calculate_entropy(domain)
            if entropy > self.dns_tunneling_thresholds['entropy_threshold']:
                return True
            
            # Check base64-like content
            base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
            base64_ratio = sum(1 for char in domain if char in base64_chars) / len(domain)
            if base64_ratio > self.dns_tunneling_thresholds['base64_ratio']:
                return True
            
            return False
        except Exception as e:
            logger.error(f"Error analyzing domain {domain}: {e}")
            return False
    
    def _convert_to_serializable(self, obj):
        """Convert numpy types to standard Python types"""
        if isinstance(obj, (np.integer, np.floating)):
            return int(obj) if isinstance(obj, np.integer) else float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        return obj
    
    def extract_pcap_features(self, pcap_path):
        """
        Extract network features from a PCAP file
        
        Args:
            pcap_path (Path): Path to the PCAP file
        
        Returns:
            str: Path to the generated feature file, or None if error
        """
        try:
            # Ensure path is converted to string
            packets = rdpcap(str(pcap_path))
            
            # Enhanced feature extraction
            features: Dict[str, Any] = {
                "timestamp": time.time(),
                "total_packets": len(packets),
                "protocol_dist": {
                    "TCP": sum(1 for p in packets if TCP in p),
                    "UDP": sum(1 for p in packets if UDP in p),
                    "ICMP": sum(1 for p in packets if IP in p and p[IP].proto == 1)
                },
                "source_ips": list(set(p[IP].src for p in packets if IP in p)),
                "destination_ips": list(set(p[IP].dst for p in packets if IP in p))
            }
            
            # DNS-specific features with tunneling detection
            dns_packets = [p for p in packets if DNS in p]
            if dns_packets:
                features["dns_queries"] = len(dns_packets)
                
                # Detect potential DNS tunneling
                tunneling_indicators = []
                for p in dns_packets:
                    try:
                        # Extract domain name
                        if hasattr(p[DNS], 'qd') and p[DNS].qd:
                            domain = p[DNS].qd.qname.decode('ascii', 'ignore')
                            
                            # Check for tunneling indicators
                            if self._is_potential_dns_tunneling(domain):
                                tunneling_indicators.append(domain)
                    except Exception as e:
                        logger.error(f"Error processing DNS packet: {e}")
                
                # Store tunneling indicators
                features["dns_tunneling_indicators"] = len(tunneling_indicators)
                features["suspicious_domains"] = tunneling_indicators
            
            # Convert numpy types and ensure JSON serializability
            features = {k: self._convert_to_serializable(v) for k, v in features.items()}
            
            # Generate output filename with timestamp
            output_file = self.output_dir / f"packet_{time.time()}.json"
            
            # Ensure valid JSON formatting with error handling
            try:
                with open(output_file, 'w') as f:
                    json.dump(features, f, indent=2)
                
                logger.info(f"Features extracted and saved to {output_file}")
                return str(output_file)
            except IOError as io_err:
                logger.error(f"IO Error writing features: {io_err}")
                return None
        
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
    else:
        print("Feature extraction failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
