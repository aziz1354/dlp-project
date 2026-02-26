#!/usr/bin/env python3
import time
from pathlib import Path
from feature_extractor import FeatureExtractor
import shutil
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PCAPProcessor:
    def __init__(self):
        self.suricata_pcap_dir = Path("/var/log/suricata")
        self.processed_dir = Path("/root/dlp_project/processed_pcaps")
        self.processed_dir.mkdir(exist_ok=True)
        self.extractor = FeatureExtractor()
        logger.info("PCAP Processor initialized")
        
    def process_existing_pcaps(self):
        """Process any existing PCAP files"""
        for pcap in self.suricata_pcap_dir.glob("pcap.log*"):
            self._process_pcap(pcap)
            
    def monitor_and_process(self):
        """Monitor for new PCAP files and process them"""
        logger.info("Starting PCAP monitoring...")
        self.process_existing_pcaps()
        
        while True:
            try:
                time.sleep(5)
                self.process_existing_pcaps()
            except KeyboardInterrupt:
                logger.info("Stopping PCAP monitoring")
                break
            except Exception as e:
                logger.error(f"Error in monitoring: {str(e)}")
                time.sleep(10)

    def _process_pcap(self, pcap_path):
        """Process a single PCAP file"""
        try:
            logger.info(f"Processing {pcap_path.name}...")
            
            # Extract features
            feature_file = self.extractor.extract_pcap_features(pcap_path)
            
            if feature_file:
                # Move processed PCAP to archive
                dest = self.processed_dir / pcap_path.name
                shutil.move(str(pcap_path), str(dest))
                logger.info(f"Processed {pcap_path.name}, features saved to {feature_file}")
        except Exception as e:
            logger.error(f"Error processing {pcap_path}: {str(e)}")

if __name__ == "__main__":
    processor = PCAPProcessor()
    processor.monitor_and_process()
