# Network Module - Installation

## System
- Ubuntu 20.04
- Python 3.8.10

## System Packages
- Suricata 7.0.10
- YARA 3.9.0
- libyara3 3.9.0

## Python Packages
- scapy 2.6.1
- scikit-learn 1.3.2
- numpy 1.24.4
- scipy 1.10.1
- joblib 1.4.2

## Web Module
- mitmproxy 4.0.4

## Setup
1. Install Suricata and YARA via apt
2. pip3 install scapy scikit-learn numpy scipy joblib
3. Copy dlp.rules to /etc/suricata/rules/
4. Run suricata with suricata.yaml config
5. Install mitmproxy certificate (web/certs/) in browser
