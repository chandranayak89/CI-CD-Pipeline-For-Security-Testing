"""
Packet capture module for the Security Testing Pipeline.
This module is responsible for capturing network packets.
"""

import logging
import threading
import time
from scapy.all import sniff, wrpcap, rdpcap

logger = logging.getLogger("Security-Pipeline-PacketCapture")

class PacketCapture:
    """
    Class for capturing network packets from an interface or reading from a PCAP file.
    """
    def __init__(self, traffic_analyzer, interface=None, pcap_file=None):
        """
        Initialize the packet capture.
        
        Args:
            traffic_analyzer: The traffic analyzer to pass captured packets to
            interface: Network interface to capture from
            pcap_file: PCAP file to read packets from
        """
        self.traffic_analyzer = traffic_analyzer
        self.interface = interface
        self.pcap_file = pcap_file
        self.stop_flag = threading.Event()
        self.capture_thread = None
        self.packet_count = 0
        self.start_time = None

    def packet_handler(self, packet):
        """
        Process each captured packet.
        
        Args:
            packet: The captured packet
        """
        self.packet_count += 1
        
        # Send packet to analyzer
        self.traffic_analyzer.analyze_packet(packet)
        
        # Log packet count every 1000 packets
        if self.packet_count % 1000 == 0:
            elapsed = time.time() - self.start_time
            rate = self.packet_count / elapsed if elapsed > 0 else 0
            logger.info(f"Processed {self.packet_count} packets ({rate:.2f} packets/sec)")
        
        return self.stop_flag.is_set()
    
    def start_capture(self):
        """Start capturing packets."""
        if self.capture_thread and self.capture_thread.is_alive():
            logger.warning("Packet capture already running")
            return
        
        self.stop_flag.clear()
        self.packet_count = 0
        self.start_time = time.time()
        
        # Create a new thread for packet capture
        self.capture_thread = threading.Thread(
            target=self._capture_packets,
            daemon=True
        )
        self.capture_thread.start()
        
        logger.info("Packet capture started")

    def _capture_packets(self):
        """Internal method to perform packet capture."""
        try:
            if self.pcap_file:
                # Read from PCAP file
                logger.info(f"Reading packets from {self.pcap_file}")
                packets = rdpcap(self.pcap_file)
                for packet in packets:
                    if self.stop_flag.is_set():
                        break
                    self.packet_handler(packet)
                    # Simulate real-time capture
                    time.sleep(0.001)
            else:
                # Capture from network interface
                interface = self.interface or "eth0"  # Default to eth0 if None
                logger.info(f"Starting packet capture on interface {interface}")
                
                # Start sniffing packets
                sniff(
                    iface=interface,
                    prn=self.packet_handler,
                    stop_filter=lambda _: self.stop_flag.is_set()
                )
        except Exception as e:
            logger.error(f"Error in packet capture: {str(e)}", exc_info=True)
        finally:
            logger.info("Packet capture stopped")
    
    def stop_capture(self):
        """Stop capturing packets."""
        if not self.capture_thread or not self.capture_thread.is_alive():
            logger.warning("No packet capture running")
            return
        
        self.stop_flag.set()
        self.capture_thread.join(timeout=5.0)
        
        if self.capture_thread.is_alive():
            logger.warning("Failed to stop packet capture thread gracefully")
        else:
            logger.info("Packet capture thread stopped successfully")
            
        elapsed = time.time() - self.start_time
        logger.info(f"Capture summary: {self.packet_count} packets in {elapsed:.2f} seconds")
    
    def save_to_pcap(self, filename, packets):
        """
        Save packets to a PCAP file.
        
        Args:
            filename: The name of the PCAP file
            packets: The packets to save
        """
        try:
            wrpcap(filename, packets)
            logger.info(f"Saved {len(packets)} packets to {filename}")
            return True
        except Exception as e:
            logger.error(f"Error saving PCAP file: {str(e)}", exc_info=True)
            return False 