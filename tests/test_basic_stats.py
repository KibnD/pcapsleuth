#!/usr/bin/env python3
"""
Unit tests for basic statistics analyzer
"""
import unittest
import sys
import os
from unittest.mock import Mock, patch

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from pcapsleuth.analysis.basic_stats import BasicStatsAnalyzer
    from pcapsleuth.models import AnalysisResult
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure you're running from the project root directory")
    sys.exit(1)

class TestBasicStatsAnalyzer(unittest.TestCase):
    """Test cases for BasicStatsAnalyzer"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.analyzer = BasicStatsAnalyzer()
        
    def test_analyzer_initialization(self):
        """Test that analyzer initializes correctly"""
        self.assertIsNotNone(self.analyzer)
        self.assertEqual(self.analyzer.name, "Basic Statistics")
        
    def test_empty_packet_list(self):
        """Test analyzer with empty packet list"""
        packets = []
        result = self.analyzer.analyze(packets)
        
        self.assertIsInstance(result, AnalysisResult)
        self.assertEqual(result.total_packets, 0)
        self.assertEqual(result.protocol_counts, {})
        
    def test_packet_counting(self):
        """Test basic packet counting functionality"""
        # Create mock packets
        mock_packets = []
        
        # Mock TCP packet
        tcp_packet = Mock()
        tcp_packet.haslayer.return_value = True
        tcp_packet.__class__.__name__ = "TCP"
        mock_packets.append(tcp_packet)
        
        # Mock UDP packet
        udp_packet = Mock()
        udp_packet.haslayer.return_value = True
        udp_packet.__class__.__name__ = "UDP"
        mock_packets.append(udp_packet)
        
        # Mock another TCP packet
        tcp_packet2 = Mock()
        tcp_packet2.haslayer.return_value = True
        tcp_packet2.__class__.__name__ = "TCP"
        mock_packets.append(tcp_packet2)
        
        # Configure haslayer method for protocol detection
        def mock_haslayer(protocol):
            if protocol == "TCP":
                return tcp_packet.haslayer.return_value or tcp_packet2.haslayer.return_value
            elif protocol == "UDP":
                return udp_packet.haslayer.return_value
            return False
        
        for packet in mock_packets:
            packet.haslayer.side_effect = mock_haslayer
        
        result = self.analyzer.analyze(mock_packets)
        
        self.assertEqual(result.total_packets, 3)
        
    def test_protocol_distribution(self):
        """Test protocol distribution calculation"""
        # This test would require more sophisticated mocking
        # For now, test basic functionality
        packets = []
        result = self.analyzer.analyze(packets)
        
        self.assertIsInstance(result.protocol_counts, dict)
        
    def test_size_statistics(self):
        """Test packet size statistics"""
        # Create mock packets with size information
        mock_packets = []
        
        packet1 = Mock()
        packet1.__len__ = lambda: 64
        packet1.haslayer.return_value = False
        mock_packets.append(packet1)
        
        packet2 = Mock()
        packet2.__len__ = lambda: 128
        packet2.haslayer.return_value = False
        mock_packets.append(packet2)
        
        packet3 = Mock()
        packet3.__len__ = lambda: 256
        packet3.haslayer.return_value = False
        mock_packets.append(packet3)
        
        result = self.analyzer.analyze(mock_packets)
        
        self.assertEqual(result.total_packets, 3)
        # Additional size-related assertions would go here
        
    def test_time_analysis(self):
        """Test time-based analysis"""
        # Mock packets with timestamp information
        mock_packets = []
        
        packet = Mock()
        packet.time = 1625097600.0  # Mock timestamp
        packet.haslayer.return_value = False
        mock_packets.append(packet)
        
        result = self.analyzer.analyze(mock_packets)
        
        self.assertIsNotNone(result)
        
    def test_analyze_returns_analysis_result(self):
        """Test that analyze method returns AnalysisResult object"""
        packets = []
        result = self.analyzer.analyze(packets)
        
        self.assertIsInstance(result, AnalysisResult)
        self.assertTrue(hasattr(result, 'total_packets'))
        self.assertTrue(hasattr(result, 'protocol_counts'))
        self.assertTrue(hasattr(result, 'analyzer'))
        
    def test_analyzer_name_property(self):
        """Test analyzer name property"""
        self.assertEqual(self.analyzer.name, "Basic Statistics")
        
    def test_analyzer_description_property(self):
        """Test analyzer description property"""
        self.assertTrue(hasattr(self.analyzer, 'description'))
        self.assertIsInstance(self.analyzer.description, str)
        
    def test_large_packet_count(self):
        """Test analyzer with large number of packets"""
        # Create a large number of mock packets
        mock_packets = []
        for i in range(1000):
            packet = Mock()
            packet.haslayer.return_value = False
            packet.__len__ = lambda: 64
            mock_packets.append(packet)
        
        result = self.analyzer.analyze(mock_packets)
        
        self.assertEqual(result.total_packets, 1000)
        
    def test_mixed_protocols(self):
        """Test with mixed protocol packets"""
        # This would test the analyzer's ability to handle
        # various protocol types correctly
        packets = []
        result = self.analyzer.analyze(packets)
        
        self.assertIsInstance(result, AnalysisResult)

class TestBasicStatsIntegration(unittest.TestCase):
    """Integration tests for BasicStatsAnalyzer"""
    
    def test_with_scapy_packets(self):
        """Test with actual Scapy packets if available"""
        try:
            from scapy.all import IP, TCP, UDP, Raw
            
            # Create real Scapy packets
            packets = [
                IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=80, dport=8080),
                IP(src="192.168.1.2", dst="192.168.1.1") / UDP(sport=53, dport=5353),
                IP(src="192.168.1.1", dst="192.168.1.3") / TCP(sport=443, dport=8443) / Raw(load="test")
            ]
            
            analyzer = BasicStatsAnalyzer()
            result = analyzer.analyze(packets)
            
            self.assertEqual(result.total_packets, 3)
            self.assertIn('TCP', result.protocol_counts)
            self.assertIn('UDP', result.protocol_counts)
            
        except ImportError:
            self.skipTest("Scapy not available for integration testing")

if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)