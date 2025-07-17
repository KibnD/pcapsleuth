from collections import Counter
from typing import List
from scapy.all import TCP, Raw
from pcapsleuth.models import HTTPAnalysisResult
import logging

logger = logging.getLogger(__name__)

class HTTPAnalyzer:
    name = "HTTP Analyzer"
    description = "Analyzes HTTP traffic for requests and statistics"

    def __init__(self):
        self.http_request_count = 0
        self.methods_counter = Counter()
        self.host_counter = Counter()
        self.url_counter = Counter()
        self.errors = []
        self.processed_requests = set()  # Track processed requests to avoid duplicates

    def process_packet(self, packet, state, results, config):
        try:
            # Only process TCP packets on HTTP ports
            if not (TCP in packet and (packet[TCP].sport in [80, 8080, 8000] or 
                                     packet[TCP].dport in [80, 8080, 8000])):
                return

            # Check if packet has payload
            if not packet.haslayer(Raw):
                return

            try:
                payload = packet[Raw].load
                
                # Try to decode as UTF-8, fallback to latin-1 if that fails
                try:
                    payload_str = payload.decode('utf-8', errors='ignore')
                except UnicodeDecodeError:
                    payload_str = payload.decode('latin-1', errors='ignore')
                
                # Check for HTTP request pattern
                if not self._is_http_request(payload_str):
                    return

                # Create request identifier to avoid duplicates
                src_ip = packet.src if hasattr(packet, 'src') else 'unknown'
                dst_ip = packet.dst if hasattr(packet, 'dst') else 'unknown'
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                
                # Use first line as part of identifier
                first_line = payload_str.split('\r\n')[0] if '\r\n' in payload_str else payload_str.split('\n')[0]
                request_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{hash(first_line)}"
                
                # Skip if already processed
                if request_id in self.processed_requests:
                    return
                
                self.processed_requests.add(request_id)
                self.http_request_count += 1
                
                # Parse HTTP request
                self._parse_http_request(payload_str)
                
            except Exception as decode_error:
                logger.debug(f"Error decoding HTTP payload: {decode_error}")
                
        except Exception as e:
            error_msg = f"Error processing HTTP packet: {e}"
            logger.debug(error_msg)
            self.errors.append(error_msg)

    def _is_http_request(self, payload_str):
        """Check if payload contains HTTP request"""
        if not payload_str:
            return False
            
        # Check for HTTP request methods
        http_methods = ['GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ', 'TRACE ', 'CONNECT ']
        
        # Check if payload starts with HTTP method and contains HTTP version
        starts_with_method = any(payload_str.startswith(method) for method in http_methods)
        contains_http_version = 'HTTP/1.' in payload_str or 'HTTP/2' in payload_str
        
        return starts_with_method and contains_http_version

    def _parse_http_request(self, payload_str):
        """Parse HTTP request to extract method, URL, and host"""
        try:
            # Split into lines
            lines = payload_str.replace('\r\n', '\n').split('\n')
            
            if not lines:
                return
                
            # Parse first line (request line)
            first_line = lines[0].strip()
            parts = first_line.split()
            
            if len(parts) >= 2:
                method = parts[0].upper()
                url = parts[1]
                
                # Clean and validate method
                if method in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT']:
                    self.methods_counter[method] += 1
                    
                # Clean and store URL (limit length to prevent memory issues)
                if len(url) <= 1000:  # Reasonable URL length limit
                    self.url_counter[url] += 1
                else:
                    self.url_counter[url[:1000] + '...'] += 1
            
            # Parse headers
            host = None
            for line in lines[1:]:
                line = line.strip()
                if not line:
                    break  # Empty line indicates end of headers
                    
                # Look for Host header
                if line.lower().startswith('host:'):
                    host_parts = line.split(':', 1)
                    if len(host_parts) > 1:
                        host = host_parts[1].strip()
                        # Clean host (remove port if present)
                        if ':' in host:
                            host = host.split(':')[0]
                        
                        # Validate host format
                        if host and len(host) <= 253:  # Valid hostname length
                            self.host_counter[host] += 1
                        break
                        
        except Exception as e:
            logger.debug(f"Error parsing HTTP request: {e}")

    def finalize(self, state, results, config):
        results.http_analysis = HTTPAnalysisResult(
            total_http_requests=self.http_request_count,
            http_methods=dict(self.methods_counter),
            hostnames=dict(self.host_counter.most_common(50)),  # Limit to top 50
            urls=dict(self.url_counter.most_common(100)),  # Limit to top 100
            errors=self.errors
        )