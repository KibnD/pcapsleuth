
from scapy.layers.inet import IP
import logging

logger = logging.getLogger(__name__)

class BasicStatsAnalyzer:
    """Basic statistics analyzer"""
    
    def process_packet(self, packet, state, results, config):
        """Process packet for basic statistics"""
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = ip_layer.proto
            
            # Update counters
            conversation = f"{src_ip} <-> {dst_ip}"
            state.talker_counter[conversation] += 1
            state.protocol_counter[protocol] += 1
    
    def finalize(self, state, results, config):
        """Finalize basic statistics"""
        logger.debug("Basic statistics finalized")