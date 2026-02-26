#!/usr/bin/env python3
import json
from pathlib import Path
import logging
import time
from typing import Dict, Any, List

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='/var/log/dlp/anomaly_detector.log',
    filemode='a'
)
logger = logging.getLogger(__name__)

class DNSAnomalyDetector:
    def __init__(self):
        self.feature_dir = Path("/root/dlp_project/processed_features")
        self.anomaly_dir = Path("/root/dlp_project/anomaly_reports")
        self.anomaly_dir.mkdir(exist_ok=True)
        
        # Anomaly detection thresholds
        self.thresholds = {
            'dns_query_length': 100,  # Suspicious long domain names
            'dns_query_count': 10,    # Too many DNS queries
            'total_packets': {
                'warning': 500,
                'critical': 1000
            }
        }

    def detect_dns_anomalies(self, features: Dict[str, Any]) -> List[str]:
        """
        Detect potential DNS-related anomalies
        
        Args:
            features (dict): Extracted network features
        
        Returns:
            list: Detected anomaly reasons
        """
        anomalies: List[str] = []
        
        # Check for suspicious DNS query characteristics
        if features.get('dns_tunneling_indicators', 0) > 0:
            anomalies.append("Potential DNS Tunneling")
        
        # Check total DNS queries
        dns_query_count = features.get('dns_queries', 0)
        if dns_query_count > self.thresholds['dns_query_count']:
            anomalies.append(f"High DNS Query Count: {dns_query_count}")
        
        # Check total packet count
        total_packets = features.get('total_packets', 0)
        if total_packets > self.thresholds['total_packets']['critical']:
            anomalies.append(f"Excessive Packet Volume: {total_packets}")
        elif total_packets > self.thresholds['total_packets']['warning']:
            anomalies.append(f"High Packet Volume: {total_packets}")
        
        return anomalies

    def process_features(self, feature_file: Path):
        """
        Process a feature file and generate anomaly report if needed
        
        Args:
            feature_file (Path): Path to the feature JSON file
        """
        try:
            with open(feature_file, 'r') as f:
                features = json.load(f)
            
            # Detect anomalies
            anomalies = self.detect_dns_anomalies(features)
            
            # Generate anomaly report if anomalies found
            if anomalies:
                self._log_anomaly(feature_file, features, anomalies)
        
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in {feature_file}")
        except Exception as e:
            logger.error(f"Error processing {feature_file}: {str(e)}")

    def _log_anomaly(self, file: Path, features: Dict[str, Any], reasons: List[str]):
        """
        Log detected anomalies to a JSON report
        
        Args:
            file (Path): Source feature file
            features (dict): Original feature data
            reasons (list): List of anomaly reasons
        """
        report = {
            "timestamp": features.get("timestamp", time.time()),
            "source_file": str(file),
            "total_packets": features.get('total_packets', 0),
            "anomaly_reasons": reasons
        }
        
        # Generate unique anomaly report filename
        report_file = self.anomaly_dir / f"anomaly_{file.stem}.json"
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Anomaly report generated: {report_file}")

    def detect(self):
        """
        Main detection loop to process feature files
        """
        for feature_file in sorted(self.feature_dir.glob('*.json')):
            self.process_features(feature_file)

def main():
    detector = DNSAnomalyDetector()
    detector.detect()

if __name__ == "__main__":
    main()
