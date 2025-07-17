from collections import Counter
from typing import List
from scapy.all import TCP, Raw
from scapy.layers.tls.all import TLSClientHello, TLS_Ext_ServerName, TLS
from pcapsleuth.models import TLSAnalysisResult
import logging

logger = logging.getLogger(__name__)

class TLSAnalyzer:
    name = "TLS Analyzer"
    description = "Analyzes TLS traffic for sessions and versions"

    def __init__(self):
        self.total_tls_sessions = 0
        self.tls_versions_counter = Counter()
        self.cert_hosts_counter = Counter()
        self.errors = []
        self.processed_flows = set()  # Track processed flows to avoid duplicates

    def process_packet(self, packet, state, results, config):
        try:
            # Only process TCP packets on common TLS ports
            if not (TCP in packet and (packet[TCP].sport == 443 or packet[TCP].dport == 443 or
                                     packet[TCP].sport == 8443 or packet[TCP].dport == 8443)):
                return

            # Create flow identifier to avoid processing same flow multiple times
            src_ip = packet.src if hasattr(packet, 'src') else 'unknown'
            dst_ip = packet.dst if hasattr(packet, 'dst') else 'unknown'
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"

            # Check if packet contains TLS data
            if packet.haslayer(TLS):
                tls_layer = packet[TLS]
                
                # Process TLS Client Hello
                if packet.haslayer(TLSClientHello):
                    # Only count unique flows
                    if flow_id not in self.processed_flows:
                        self.processed_flows.add(flow_id)
                        self.total_tls_sessions += 1
                        
                    client_hello = packet[TLSClientHello]
                    
                    # Extract TLS version
                    if hasattr(client_hello, 'version'):
                        version = client_hello.version
                        self.tls_versions_counter[version] += 1
                    
                    # Extract SNI from extensions
                    if hasattr(client_hello, 'ext') and client_hello.ext:
                        for ext in client_hello.ext:
                            if hasattr(ext, 'servername') and ext.servername:
                                try:
                                    if isinstance(ext.servername, bytes):
                                        server_name = ext.servername.decode('utf-8', errors='ignore')
                                    else:
                                        server_name = str(ext.servername)
                                    
                                    if server_name and server_name.strip():
                                        self.cert_hosts_counter[server_name.strip()] += 1
                                except Exception as e:
                                    logger.debug(f"Error processing SNI: {e}")
                                    
            # Alternative: Parse raw TLS data if scapy TLS parsing fails
            elif Raw in packet and packet[TCP].dport == 443:
                try:
                    payload = packet[Raw].load
                    if len(payload) > 5:
                        # Check for TLS handshake (content type 22)
                        if payload[0] == 0x16:
                            # Check for Client Hello (handshake type 1)
                            if len(payload) > 5 and payload[5] == 0x01:
                                if flow_id not in self.processed_flows:
                                    self.processed_flows.add(flow_id)
                                    self.total_tls_sessions += 1
                                    
                                # Extract TLS version from Client Hello
                                if len(payload) > 9:
                                    version = (payload[9] << 8) | payload[10]
                                    self.tls_versions_counter[version] += 1
                                    
                                # Try to extract SNI
                                sni = self._extract_sni_from_raw(payload)
                                if sni:
                                    self.cert_hosts_counter[sni] += 1
                                    
                except Exception as e:
                    logger.debug(f"Error parsing raw TLS data: {e}")
                    
        except Exception as e:
            error_msg = f"Error processing TLS packet: {e}"
            logger.debug(error_msg)
            self.errors.append(error_msg)

    def _extract_sni_from_raw(self, payload):
        """Extract SNI from raw TLS Client Hello payload"""
        try:
            # Skip TLS record header (5 bytes) and handshake header (4 bytes)
            offset = 9
            if len(payload) < offset + 2:
                return None
                
            # Skip version (2 bytes)
            offset += 2
            
            # Skip random (32 bytes)
            offset += 32
            if len(payload) < offset + 1:
                return None
                
            # Skip session ID
            session_id_len = payload[offset]
            offset += 1 + session_id_len
            if len(payload) < offset + 2:
                return None
                
            # Skip cipher suites
            cipher_suites_len = (payload[offset] << 8) | payload[offset + 1]
            offset += 2 + cipher_suites_len
            if len(payload) < offset + 1:
                return None
                
            # Skip compression methods
            compression_len = payload[offset]
            offset += 1 + compression_len
            if len(payload) < offset + 2:
                return None
                
            # Parse extensions
            extensions_len = (payload[offset] << 8) | payload[offset + 1]
            offset += 2
            
            end_offset = offset + extensions_len
            while offset < end_offset - 4:
                # Extension type and length
                ext_type = (payload[offset] << 8) | payload[offset + 1]
                ext_len = (payload[offset + 2] << 8) | payload[offset + 3]
                offset += 4
                
                # Check for SNI extension (type 0)
                if ext_type == 0 and offset + ext_len <= len(payload):
                    return self._parse_sni_extension(payload[offset:offset + ext_len])
                    
                offset += ext_len
                
        except Exception as e:
            logger.debug(f"Error extracting SNI from raw data: {e}")
            
        return None

    def _parse_sni_extension(self, ext_data):
        """Parse SNI extension data"""
        try:
            if len(ext_data) < 5:
                return None
                
            # Skip server name list length (2 bytes)
            offset = 2
            
            # Check name type (1 byte, should be 0 for hostname)
            if ext_data[offset] != 0:
                return None
            offset += 1
            
            # Get hostname length
            hostname_len = (ext_data[offset] << 8) | ext_data[offset + 1]
            offset += 2
            
            if offset + hostname_len <= len(ext_data):
                hostname = ext_data[offset:offset + hostname_len].decode('utf-8', errors='ignore')
                return hostname.strip() if hostname else None
                
        except Exception as e:
            logger.debug(f"Error parsing SNI extension: {e}")
            
        return None

    def finalize(self, state, results, config):
        # Convert version numbers to readable format
        readable_versions = {}
        for version, count in self.tls_versions_counter.items():
            if version == 0x0301:
                readable_versions["TLS 1.0"] = count
            elif version == 0x0302:
                readable_versions["TLS 1.1"] = count
            elif version == 0x0303:
                readable_versions["TLS 1.2"] = count
            elif version == 0x0304:
                readable_versions["TLS 1.3"] = count
            else:
                readable_versions[f"TLS {version}"] = count
        
        results.tls_analysis = TLSAnalysisResult(
            total_tls_sessions=self.total_tls_sessions,
            tls_versions=readable_versions,
            certificate_hosts=dict(self.cert_hosts_counter.most_common(20)),  # Limit to top 20
            errors=self.errors
        )