
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP
import math
from collections import Counter
import logging

logger = logging.getLogger(__name__)

class DNSAnalyzer:
    """DNS analyzer with tunneling detection"""
    
    def __init__(self):
        self.txt_query_sources = Counter()
    
    def process_packet(self, packet, state, results, config):
        """Process DNS packets"""
        if not packet.haslayer(DNS):
            return
        
        dns_layer = packet[DNS]
        
        # Only process queries
        if dns_layer.qr != 0:  # 0 = query, 1 = response
            return
        
        if packet.haslayer(DNSQR):
            try:
                query_name = packet[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                query_type = packet[DNSQR].qtype
                
                # Update DNS query counter
                state.dns_counter[query_name] += 1
                
                # Analyze for tunneling
                self._analyze_tunneling(packet, query_name, query_type, results, config)
                
            except Exception as e:
                logger.warning(f"DNS processing error: {e}")
    
    def _analyze_tunneling(self, packet, query_name: str, query_type: int, results, config):
        """Analyze DNS query for tunneling indicators"""
        try:
            src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
            
            # Check query length and entropy
            if len(query_name) > config.dns_max_query_length:
                entropy = self._calculate_entropy(query_name)
                if entropy > config.dns_entropy_threshold:
                    results.dns_tunneling.add_suspicious_query(
                        query_name, entropy, src_ip
                    )
            
            # Track TXT queries
            if query_type == 16:  # TXT record
                self.txt_query_sources[src_ip] += 1
                
        except Exception as e:
            logger.warning(f"Tunneling analysis error: {e}")
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0
        
        char_counts = Counter(data.lower())
        data_len = len(data)
        
        entropy = 0.0
        for count in char_counts.values():
            probability = count / data_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def finalize(self, state, results, config):
        """Finalize DNS analysis"""
        # Check for excessive TXT queries
        for src_ip, count in self.txt_query_sources.items():
            if count >= config.dns_txt_query_threshold:
                results.dns_tunneling.excessive_txt_queries[src_ip] = count
        
        logger.debug(f"DNS analysis complete. {results.dns_tunneling.total_suspicious_queries} suspicious queries found")
