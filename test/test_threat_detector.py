"""
Tests for the threat detector module.
"""

import pytest
import sys
import os
import logging
import time
from unittest.mock import MagicMock, patch
from scapy.all import IP, TCP, UDP, ICMP, Raw, Ether

# Add the src directory to the path so we can import the modules
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

# Import the modules to test
from threat_detector import ThreatDetector
from alert_system import AlertSystem

# Set up logging to avoid errors
logging.basicConfig(level=logging.ERROR)

@pytest.fixture
def alert_system():
    """Fixture for creating an alert system."""
    return MagicMock(spec=AlertSystem)

@pytest.fixture
def threat_detector(alert_system):
    """Fixture for creating a threat detector."""
    return ThreatDetector(alert_system)

def create_packet(protocol="tcp", payload=None, flags=None):
    """Helper function to create test packets."""
    packet = Ether()/IP(src="192.168.1.2", dst="10.0.0.1")
    
    if protocol.lower() == "tcp":
        tcp = TCP(sport=12345, dport=80)
        if flags is not None:
            tcp.flags = flags
        packet = packet/tcp
    elif protocol.lower() == "udp":
        packet = packet/UDP(sport=12345, dport=53)
    elif protocol.lower() == "icmp":
        packet = packet/ICMP()
    
    if payload:
        packet = packet/Raw(load=payload)
    
    return packet

class TestThreatDetector:
    """Test class for ThreatDetector."""
    
    def test_initialization(self, threat_detector):
        """Test that the threat detector initializes correctly."""
        assert threat_detector.alert_system is not None
        assert threat_detector.port_scan_threshold > 0
        assert threat_detector.packet_rate_threshold > 0
        assert threat_detector.signatures is not None
        
    def test_sql_injection_detection(self, threat_detector, alert_system):
        """Test that SQL injection is detected."""
        payload = "username=admin' OR '1'='1'; --"
        packet = create_packet(payload=payload)
        
        threat_detector.analyze_packet(packet)
        
        # Check if alert was generated
        alert_system.generate_alert.assert_called_once()
        args = alert_system.generate_alert.call_args[0]
        assert "sql injection" in args[0].lower()
        
    def test_xss_detection(self, threat_detector, alert_system):
        """Test that XSS is detected."""
        payload = "comment=<script>alert('XSS')</script>"
        packet = create_packet(payload=payload)
        
        threat_detector.analyze_packet(packet)
        
        # Check if alert was generated
        alert_system.generate_alert.assert_called_once()
        args = alert_system.generate_alert.call_args[0]
        assert "xss" in args[0].lower()
        
    def test_port_scan_detection(self, threat_detector, alert_system):
        """Test that port scans are detected."""
        src_ip = "192.168.1.2"
        dst_ip = "10.0.0.1"
        
        # Create packets to different ports from the same source
        for port in range(1, threat_detector.port_scan_threshold + 2):
            packet = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=12345, dport=port)
            threat_detector.analyze_packet(packet)
        
        # Check if alert was generated
        alert_system.generate_alert.assert_called_once()
        args = alert_system.generate_alert.call_args[0]
        assert "port scan" in args[0].lower()
        
    def test_fin_scan_detection(self, threat_detector, alert_system):
        """Test that FIN scans are detected."""
        packet = create_packet(flags=0x01)  # FIN flag
        
        threat_detector.analyze_packet(packet)
        
        # Check if alert was generated
        alert_system.generate_alert.assert_called_once()
        args = alert_system.generate_alert.call_args[0]
        assert "fin scan" in args[0].lower()
        
    def test_xmas_scan_detection(self, threat_detector, alert_system):
        """Test that XMAS scans are detected."""
        packet = create_packet(flags=0x29)  # FIN, PSH, URG flags
        
        threat_detector.analyze_packet(packet)
        
        # Check if alert was generated
        alert_system.generate_alert.assert_called_once()
        args = alert_system.generate_alert.call_args[0]
        assert "xmas scan" in args[0].lower()
        
    def test_null_scan_detection(self, threat_detector, alert_system):
        """Test that NULL scans are detected."""
        packet = create_packet(flags=0)  # No flags
        
        threat_detector.analyze_packet(packet)
        
        # Check if alert was generated
        alert_system.generate_alert.assert_called_once()
        args = alert_system.generate_alert.call_args[0]
        assert "null scan" in args[0].lower()
        
    def test_rate_based_attack_detection(self, threat_detector, alert_system):
        """Test that rate-based attacks (DoS) are detected."""
        src_ip = "192.168.1.2"
        dst_ip = "10.0.0.1"
        
        # Mock the current time
        current_time = time.time()
        with patch('time.time', return_value=current_time):
            # Create many packets to the same destination to simulate DoS
            for _ in range(threat_detector.packet_rate_threshold + 1):
                packet = Ether()/IP(src=src_ip, dst=dst_ip)/TCP(sport=12345, dport=80)
                threat_detector.analyze_packet(packet)
            
            # Check if alert was generated
            alert_system.generate_alert.assert_called_once()
            args = alert_system.generate_alert.call_args[0]
            assert "dos" in args[0].lower()
            
    def test_non_matching_packet(self, threat_detector, alert_system):
        """Test that normal traffic doesn't trigger alerts."""
        payload = "user=admin&password=12345"
        packet = create_packet(payload=payload)
        
        threat_detector.analyze_packet(packet)
        
        # Check that no alert was generated
        alert_system.generate_alert.assert_not_called() 