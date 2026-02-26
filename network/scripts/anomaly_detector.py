#!/usr/bin/env python3
import json
from pathlib import Path
import logging
import time
from typing import Dict, Any, List
import os

# Ensure log directory exists
os.makedirs('/var/log/dlp', exist_ok=True)

# Configure logging
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
        
        # Ensure directories exist
        self.feature_dir.mkdir(exist_ok=True)
        self.anomaly_dir.mkdir(exist_ok=True)
        
        # Enhanced anomaly detection thresholds
        self.thresholds = {
            'dns_tunneling_indicators': {
                'critical': 10,  # Number of long domain names
                'warning': 5
            },
            'dns_query_count': {
                'warning': 30,    # Many DNS queries
                'critical': 50    # Excessive DNS queries
            },
            'total_packets': {
                'warning': 500,
                'critical': 1000
            }
        }

    def detect_dns_anomalies(self, features: Dict[str, Any]) -> List[str]:
        """
        Detect potential DNS-related anomalies with focus on tunneling
        
        Args:
            features (dict): Extracted network features
        
        Returns:
            list: Detected anomaly reasons
        """
        anomalies: List[str] = []
        
        try:
            # Check for DNS tunneling indicators
            dns_tunneling_indicators = features.get('dns_tunneling_indicators', 0)
            if dns_tunneling_indicators >= self.thresholds['dns_tunneling_indicators']['critical']:
                anomalies.append(f"CRITICAL: Potential DNS Tunneling - {dns_tunneling_indicators} suspicious domains")
            elif dns_tunneling_indicators >= self.thresholds['dns_tunneling_indicators']['warning']:
                anomalies.append(f"WARNING: Possible DNS Tunneling - {dns_tunneling_indicators} suspicious domains")
            
            # Check total DNS queries
            dns_query_count = features.get('dns_queries', 0)
            if dns_query_count > self.thresholds['dns_query_count']['critical']:
                anomalies.append(f"CRITICAL: Excessive DNS Queries: {dns_query_count}")
            elif dns_query_count > self.thresholds['dns_query_count']['warning']:
                anomalies.append(f"WARNING: High DNS Query Count: {dns_query_count}")
            
            # Check total packet count
            total_packets = features.get('total_packets', 0)
            if total_packets > self.thresholds['total_packets']['critical']:
                anomalies.append(f"CRITICAL: Excessive Packet Volume: {total_packets}")
            elif total_packets > self.thresholds['total_packets']['warning']:
                anomalies.append(f"WARNING: High Packet Volume: {total_packets}")
            
            return anomalies
        
        except Exception as e:
            logger.error(f"Error in anomaly detection: {e}")
            return []

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
            # Optional: Remove the invalid file
            try:
                os.remove(feature_file)
                logger.info(f"Removed invalid feature file: {feature_file}")
            except Exception as e:
                logger.error(f"Could not remove invalid file {feature_file}: {e}")
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
        try:
            report = {
                "timestamp": features.get("timestamp", time.time()),
                "source_file": str(file),
                "source_ips": features.get('source_ips', []),
                "destination_ips": features.get('destination_ips', []),
                "total_packets": features.get('total_packets', 0),
                "dns_queries": features.get('dns_queries', 0),
                "dns_tunneling_indicators": features.get('dns_tunneling_indicators', 0),
                "anomaly_reasons": reasons
            }
            
            # Generate unique anomaly report filename
            report_file = self.anomaly_dir / f"dns_anomaly_{file.stem}.json"
            
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            logger.warning(f"DNS Anomaly report generated: {report_file}")
        
        except Exception as e:
            logger.error(f"Failed to log anomaly: {e}")

    def detect(self):
        """
        Main detection loop to process feature files
        """
        try:
            # Remove old feature files
            self._cleanup_old_features()
            
            # Process feature files
            feature_files = sorted(self.feature_dir.glob('*.json'))
            
            if not feature_files:
                logger.info("No feature files to process")
                return
            
            for feature_file in feature_files:
                self.process_features(feature_file)
        
        except Exception as e:
            logger.error(f"Error in detection loop: {e}")

    def _cleanup_old_features(self, max_age_hours=24):
        """
        Remove feature files older than specified hours
        
        Args:
            max_age_hours (int): Maximum age of feature files in hours
        """
        try:
            current_time = time.time()
            for feature_file in self.feature_dir.glob('*.json'):
                file_age = current_time - feature_file.stat().st_mtime
                if file_age > (max_age_hours * 3600):
                    try:
                        feature_file.unlink()
                        logger.info(f"Removed old feature file: {feature_file}")
                    except Exception as e:
                        logger.error(f"Could not remove old feature file {feature_file}: {e}")
        except Exception as e:
            logger.error(f"Error in feature cleanup: {e}")

def main():
    detector = DNSAnomalyDetector()
    detector.detect()

if __name__ == "__main__":
    main()
