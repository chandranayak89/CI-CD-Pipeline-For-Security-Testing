#!/usr/bin/env python3
"""
CI/CD Pipeline for Security Testing - Main module.
This module serves as the entry point for the IDS system within the security pipeline.
"""

import argparse
import logging
import sys
import os
from datetime import datetime

# Import project modules
from packet_capture import PacketCapture
from traffic_analyzer import TrafficAnalyzer
from threat_detector import ThreatDetector
from alert_system import AlertSystem
from web_dashboard import start_dashboard

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f"ids_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger("Security-Pipeline-Main")

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Security Testing Pipeline - Intrusion Detection Component')
    parser.add_argument('-i', '--interface', type=str, default=None, 
                        help='Network interface to capture packets from')
    parser.add_argument('-f', '--file', type=str, default=None,
                        help='PCAP file to analyze')
    parser.add_argument('-d', '--dashboard', action='store_true',
                        help='Start the web dashboard')
    parser.add_argument('-c', '--config', type=str, default='config.yaml',
                        help='Path to configuration file')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose logging')
    
    return parser.parse_args()

def main():
    """Main function to start the security monitoring system."""
    args = parse_arguments()
    
    # Set verbose logging if requested
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    logger.info("Starting Security Monitoring System...")
    
    # Initialize components
    alert_system = AlertSystem()
    threat_detector = ThreatDetector(alert_system)
    traffic_analyzer = TrafficAnalyzer(threat_detector)
    
    # Start packet capture
    if args.file:
        logger.info(f"Reading packets from file: {args.file}")
        packet_capture = PacketCapture(traffic_analyzer, pcap_file=args.file)
    else:
        logger.info(f"Capturing packets from interface: {args.interface}")
        packet_capture = PacketCapture(traffic_analyzer, interface=args.interface)
    
    # Start the dashboard if requested
    if args.dashboard:
        logger.info("Starting web dashboard")
        start_dashboard(packet_capture, traffic_analyzer, threat_detector, alert_system)
    else:
        # Start packet capture directly
        try:
            packet_capture.start_capture()
        except KeyboardInterrupt:
            logger.info("System stopped by user")
        finally:
            logger.info("Shutting down security monitoring system...")
            packet_capture.stop_capture()

if __name__ == "__main__":
    main() 