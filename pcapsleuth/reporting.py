import json
from datetime import datetime
from typing import Any, Dict

def generate_report(results, format_type: str = 'text') -> str:
    """Generate analysis report"""
    format_type = format_type.lower()
    
    if format_type == 'json':
        return _generate_json_report(results)
    elif format_type == 'markdown':
        return _generate_markdown_report(results)
    elif format_type == 'text':
        return _generate_text_report(results)
    elif format_type == 'html':
        return _generate_html_report(results)
    else:
        raise ValueError(f"Unsupported format: {format_type}")

def _generate_json_report(results) -> str:
    """Generate JSON report"""
    report_dict = {
        'metadata': {
            'pcap_file': results.pcap_file,
            'analysis_time': results.analysis_start_time.isoformat(),
            'duration_seconds': results.analysis_duration,
            'total_packets': results.packet_count
        },
        'statistics': {
            'top_talkers': [
                {'conversation': conv, 'packets': count}
                for conv, count in results.top_talkers
            ],
            'protocols': results.protocol_distribution,
            'dns_queries': [
                {'domain': domain, 'count': count}
                for domain, count in results.dns_queries
            ],
            # Added HTTP stats
            'http': {
                'total_http_requests': results.http_analysis.total_http_requests,
                'http_methods': results.http_analysis.http_methods,
                'hostnames': results.http_analysis.hostnames,
                'urls': results.http_analysis.urls,
                'errors': results.http_analysis.errors,
            },
            # Added TLS stats with proper version mapping
            'tls': {
                'total_tls_sessions': results.tls_analysis.total_tls_sessions,
                'tls_versions': _format_tls_versions(results.tls_analysis.tls_versions),
                'certificate_hosts': results.tls_analysis.certificate_hosts,
                'errors': results.tls_analysis.errors,
            }
        },
        'threats': {
            'dns_tunneling': {
                'suspicious_queries': results.dns_tunneling.total_suspicious_queries,
                'high_entropy_queries': results.dns_tunneling.high_entropy_queries,
                'excessive_txt_queries': results.dns_tunneling.excessive_txt_queries
            },
            'icmp_floods': {
                'total_packets': results.icmp_floods.total_icmp_packets,
                'detected_floods': results.icmp_floods.potential_floods
            },
            'port_scanning': {
                'total_scan_attempts': results.port_scanning.total_scan_attempts,
                'tcp_syn_scans': results.port_scanning.tcp_syn_scans,
                'udp_scans': results.port_scanning.udp_scans,
                'stealth_scans': results.port_scanning.stealth_scans,
                'rapid_scans': results.port_scanning.rapid_scans,
                'open_ports': results.port_scanning.open_ports
            }
        },
        'errors': results.errors
    }
    
    return json.dumps(report_dict, indent=2, default=str)

def _format_tls_versions(tls_versions: dict) -> dict:
    """Convert TLS version numbers to human-readable format (robust to string/int keys)"""
    version_map = {
        768: 'TLS 1.0',
        769: 'TLS 1.1',
        770: 'TLS 1.2',
        771: 'TLS 1.3',
        772: 'TLS 1.3 (draft)',
        # Add SSL versions for completeness
        768: 'SSL 3.0',
        769: 'TLS 1.0',
    }
    formatted = {}
    for version, count in tls_versions.items():
        try:
            v_int = int(version)
            v_str = version_map.get(v_int, f'Unknown ({version})')
        except (ValueError, TypeError):
            v_str = str(version)
        formatted[v_str] = count
    return formatted

def _calculate_percentage(value: int, total: int) -> float:
    """Calculate percentage with division by zero protection"""
    return (value / total * 100) if total > 0 else 0.0

def _generate_threat_summary(results) -> str:
    """Generate a concise threat summary"""
    threats = []
    
    if results.dns_tunneling.total_suspicious_queries > 0:
        threats.append(f"DNS Tunneling ({results.dns_tunneling.total_suspicious_queries} queries)")
    
    if results.icmp_floods.total_icmp_packets > 0:
        threats.append(f"ICMP Activity ({results.icmp_floods.total_icmp_packets} packets)")
    
    if results.port_scanning.total_scan_attempts > 0:
        scan_types = []
        if results.port_scanning.tcp_syn_scans:
            scan_types.append(f"{len(results.port_scanning.tcp_syn_scans)} TCP SYN")
        if results.port_scanning.udp_scans:
            scan_types.append(f"{len(results.port_scanning.udp_scans)} UDP")
        if results.port_scanning.stealth_scans:
            scan_types.append(f"{len(results.port_scanning.stealth_scans)} Stealth")
        if results.port_scanning.rapid_scans:
            scan_types.append(f"{len(results.port_scanning.rapid_scans)} Rapid")
        
        if scan_types:
            threats.append(f"Port Scanning ({', '.join(scan_types)})")
    
    return threats

def _generate_markdown_report(results) -> str:
    """Generate Markdown report"""
    threat_summary = _generate_threat_summary(results)
    
    report = f"""# PcapSleuth Analysis Report

## Executive Summary
- **File**: {results.pcap_file}
- **Analysis Time**: {results.analysis_start_time}
- **Duration**: {results.analysis_duration:.2f} seconds
- **Total Packets**: {results.packet_count:,}
- **Threats Detected**: {len(threat_summary)} type(s)

## Network Statistics

### Top Conversations
| Conversation | Packets | Percentage |
|-------------|---------|------------|
"""
    
    for conv, count in results.top_talkers[:10]:
        percentage = _calculate_percentage(count, results.packet_count)
        report += f"| {conv} | {count:,} | {percentage:.1f}% |\n"
    
    report += "\n### Protocol Distribution\n| Protocol | Packets | Percentage |\n|----------|---------|------------|\n"
    for proto, count in results.protocol_distribution.items():
        percentage = _calculate_percentage(count, results.packet_count)
        report += f"| {proto} | {count:,} | {percentage:.1f}% |\n"
    
    report += "\n### Top DNS Queries\n| Domain | Queries |\n|--------|----------|\n"
    for domain, count in results.dns_queries[:10]:
        report += f"| {domain} | {count} |\n"
    
    # HTTP Analysis
    report += f"""

## HTTP Analysis
- **Total HTTP Requests**: {results.http_analysis.total_http_requests:,}

### HTTP Methods
| Method | Count |
|--------|-------|
"""
    for method, count in sorted(results.http_analysis.http_methods.items(), key=lambda x: -x[1]):
        report += f"| {method} | {count} |\n"

    report += "\n### Top Hostnames\n| Hostname | Requests |\n|----------|----------|\n"
    for host, count in sorted(results.http_analysis.hostnames.items(), key=lambda x: -x[1])[:10]:
        report += f"| {host} | {count} |\n"

    # TLS Analysis with proper version formatting
    report += f"""

## TLS Analysis
- **Total TLS Sessions**: {results.tls_analysis.total_tls_sessions:,}

### TLS Versions
| Version | Count |
|---------|-------|
"""
    formatted_versions = _format_tls_versions(results.tls_analysis.tls_versions)
    for version, count in formatted_versions.items():
        report += f"| {version} | {count} |\n"

    if results.tls_analysis.certificate_hosts:
        report += "\n### Certificate Hosts (SNI)\n| Host | Count |\n|------|-------|\n"
        for host, count in sorted(results.tls_analysis.certificate_hosts.items(), key=lambda x: -x[1])[:10]:
            report += f"| {host} | {count} |\n"

    # Threats section
    report += "\n## Threat Analysis\n"
    
    if threat_summary:
        report += "### ⚠️ Threats Detected\n"
        for threat in threat_summary:
            report += f"- {threat}\n"
    else:
        report += "### ✅ No Threats Detected\n"

    report += f"""
### DNS Tunneling
- **Suspicious Queries**: {results.dns_tunneling.total_suspicious_queries}
- **High Entropy Queries**: {len(results.dns_tunneling.high_entropy_queries)}
- **Excessive TXT Queries**: {len(results.dns_tunneling.excessive_txt_queries)} sources

### ICMP Analysis
- **Total ICMP Packets**: {results.icmp_floods.total_icmp_packets}
- **Detected Floods**: {len(results.icmp_floods.potential_floods)}

### Port Scanning
- **Total Scan Attempts**: {results.port_scanning.total_scan_attempts}
- **TCP SYN Scans**: {len(results.port_scanning.tcp_syn_scans)}
- **UDP Scans**: {len(results.port_scanning.udp_scans)}
- **Stealth Scans**: {len(results.port_scanning.stealth_scans)}
- **Rapid Scans**: {len(results.port_scanning.rapid_scans)}
- **Discovered Open Ports**: {len(results.port_scanning.open_ports)} hosts
"""
    
    # Add detailed port scan information
    if results.port_scanning.tcp_syn_scans:
        report += "\n#### TCP SYN Scans Detected\n| Source IP | Target IP | Unique Ports |\n|-----------|-----------|-------------|\n"
        for scan in results.port_scanning.tcp_syn_scans[:5]:
            report += f"| {scan['source_ip']} | {scan['target_ip']} | {scan['unique_ports']} |\n"
    
    if results.port_scanning.udp_scans:
        report += "\n#### UDP Scans Detected\n| Source IP | Target IP | Unique Ports |\n|-----------|-----------|-------------|\n"
        for scan in results.port_scanning.udp_scans[:5]:
            report += f"| {scan['source_ip']} | {scan['target_ip']} | {scan['unique_ports']} |\n"
    
    if results.port_scanning.stealth_scans:
        report += "\n#### Stealth Scans Detected\n| Source IP | Scan Type | Target Count |\n|-----------|-----------|-------------|\n"
        for scan in results.port_scanning.stealth_scans[:5]:
            report += f"| {scan['source_ip']} | {scan['scan_type']} | {scan['target_count']} |\n"
    
    if results.port_scanning.rapid_scans:
        report += "\n#### Rapid Scans Detected\n| Source IP | Packets/sec |\n|-----------|-------------|\n"
        for scan in results.port_scanning.rapid_scans[:5]:
            report += f"| {scan['source_ip']} | {scan['packets_per_second']:.1f} |\n"
    
    if results.port_scanning.open_ports:
        report += "\n#### Open Ports Discovered\n| Host | Protocol | Ports |\n|------|----------|-------|\n"
        for host, protocols in list(results.port_scanning.open_ports.items())[:10]:
            for protocol, ports in protocols.items():
                ports_str = ', '.join(map(str, ports[:10]))
                if len(ports) > 10:
                    ports_str += f" (+{len(ports)-10} more)"
                report += f"| {host} | {protocol.upper()} | {ports_str} |\n"
    
    if results.errors:
        report += f"\n## Errors\n"
        for error in results.errors:
            report += f"- {error}\n"
    
    return report

def _generate_text_report(results) -> str:
    """Generate text report"""
    threat_summary = _generate_threat_summary(results)
    
    report = f"""
PcapSleuth Analysis Report
==========================

File: {results.pcap_file}
Analysis Time: {results.analysis_start_time}
Duration: {results.analysis_duration:.2f} seconds
Total Packets: {results.packet_count:,}  # Removed duplicate 'Processed packets' line

NETWORK STATISTICS
------------------

Top Conversations:
"""
    
    for conv, count in results.top_talkers[:10]:
        percentage = _calculate_percentage(count, results.packet_count)
        report += f"  {conv}: {count:,} packets ({percentage:.1f}%)\n"
    
    report += "\nProtocol Distribution:\n"
    for proto, count in results.protocol_distribution.items():
        percentage = _calculate_percentage(count, results.packet_count)
        report += f"  {proto}: {count:,} packets ({percentage:.1f}%)\n"
    
    report += "\nTop DNS Queries:\n"
    for domain, count in results.dns_queries[:10]:
        report += f"  {domain}: {count} queries\n"

    # HTTP Analysis
    report += f"""

HTTP ANALYSIS
-------------
Total HTTP Requests: {results.http_analysis.total_http_requests:,}

HTTP Methods:
"""
    for method, count in sorted(results.http_analysis.http_methods.items(), key=lambda x: -x[1]):
        report += f"  {method}: {count}\n"

    report += "\nTop Hostnames:\n"
    for host, count in sorted(results.http_analysis.hostnames.items(), key=lambda x: -x[1])[:10]:
        report += f"  {host}: {count}\n"

    if results.http_analysis.urls:
        report += "\nTop URLs:\n"
        for url, count in sorted(results.http_analysis.urls.items(), key=lambda x: -x[1])[:10]:
            report += f"  {url}: {count}\n"

    # TLS Analysis with proper version formatting
    report += f"""

TLS ANALYSIS
------------
Total TLS Sessions: {results.tls_analysis.total_tls_sessions:,}

TLS Versions:
"""
    formatted_versions = _format_tls_versions(results.tls_analysis.tls_versions)
    for version, count in formatted_versions.items():
        report += f"  {version}: {count}\n"

    if results.tls_analysis.certificate_hosts:
        report += "\nCertificate Hosts (SNI):\n"
        for host, count in sorted(results.tls_analysis.certificate_hosts.items(), key=lambda x: -x[1])[:10]:
            report += f"  {host}: {count}\n"

    # Threats section
    report += "\nTHREAT ANALYSIS\n---------------\n"
    
    if threat_summary:
        report += "⚠️  Threats Detected:\n"
        for threat in threat_summary:
            report += f"   • {threat}\n"
        report += "\n"
    else:
        report += "✅ No Threats Detected\n\n"

    report += f"""DNS Tunneling:
  Suspicious Queries: {results.dns_tunneling.total_suspicious_queries}
  High Entropy Queries: {len(results.dns_tunneling.high_entropy_queries)}
  Excessive TXT Queries: {len(results.dns_tunneling.excessive_txt_queries)} sources

ICMP Analysis:
  Total ICMP Packets: {results.icmp_floods.total_icmp_packets}
  Detected Floods: {len(results.icmp_floods.potential_floods)}

Port Scanning:
  Total Scan Attempts: {results.port_scanning.total_scan_attempts}
  TCP SYN Scans: {len(results.port_scanning.tcp_syn_scans)}
  UDP Scans: {len(results.port_scanning.udp_scans)}
  Stealth Scans: {len(results.port_scanning.stealth_scans)}
  Rapid Scans: {len(results.port_scanning.rapid_scans)}
  Discovered Open Ports: {len(results.port_scanning.open_ports)} hosts
"""
    
    # Add detailed port scan information
    if results.port_scanning.tcp_syn_scans:
        report += "\nTCP SYN Scans Detected:\n"
        for scan in results.port_scanning.tcp_syn_scans[:5]:
            report += f"  {scan['source_ip']} → {scan['target_ip']}: {scan['unique_ports']} unique ports\n"
    
    if results.port_scanning.udp_scans:
        report += "\nUDP Scans Detected:\n"
        for scan in results.port_scanning.udp_scans[:5]:
            report += f"  {scan['source_ip']} → {scan['target_ip']}: {scan['unique_ports']} unique ports\n"
    
    if results.port_scanning.stealth_scans:
        report += "\nStealth Scans Detected:\n"
        for scan in results.port_scanning.stealth_scans[:5]:
            report += f"  {scan['source_ip']}: {scan['scan_type']} scan, {scan['target_count']} targets\n"
    
    if results.port_scanning.rapid_scans:
        report += "\nRapid Scans Detected:\n"
        for scan in results.port_scanning.rapid_scans[:5]:
            report += f"  {scan['source_ip']}: {scan['packets_per_second']:.1f} packets/sec\n"
    
    if results.port_scanning.open_ports:
        report += "\nOpen Ports Discovered:\n"
        for host, protocols in list(results.port_scanning.open_ports.items())[:10]:
            for protocol, ports in protocols.items():
                ports_str = ', '.join(map(str, ports[:10]))
                if len(ports) > 10:
                    ports_str += f" (+{len(ports)-10} more)"
                report += f"  {host} ({protocol.upper()}): {ports_str}\n"
    
    if results.errors:
        report += f"\nERRORS:\n"
        for error in results.errors:
            report += f"  - {error}\n"
    
    return report

def _generate_html_report(results) -> str:
    """Generate HTML report with better styling"""
    threat_summary = _generate_threat_summary(results)
    
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PcapSleuth Analysis Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background-color: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 5px;
        }}
        .summary {{
            background-color: #ecf0f1;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .threat-detected {{
            background-color: #ffeaa7;
            border-left: 4px solid #fdcb6e;
            padding: 15px;
            margin: 10px 0;
        }}
        .no-threats {{
            background-color: #d5f4e6;
            border-left: 4px solid #00b894;
            padding: 15px;
            margin: 10px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }}
        th {{
            background-color: #3498db;
            color: white;
        }}
        tr:nth-child(even) {{
            background-color: #f2f2f2;
        }}
        .metric {{
            display: inline-block;
            margin: 10px 20px 10px 0;
        }}
        .metric-value {{
            font-weight: bold;
            color: #2c3e50;
        }}
        .warning {{
            color: #e74c3c;
        }}
        .success {{
            color: #27ae60;
        }}
        .protocol-stats {{
            display: flex;
            gap: 20px;
            margin: 20px 0;
        }}
        .protocol-card {{
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
            flex: 1;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 PcapSleuth Analysis Report</h1>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="metric">
                <strong>File:</strong> <span class="metric-value">{results.pcap_file}</span>
            </div>
            <div class="metric">
                <strong>Analysis Time:</strong> <span class="metric-value">{results.analysis_start_time}</span>
            </div>
            <div class="metric">
                <strong>Duration:</strong> <span class="metric-value">{results.analysis_duration:.2f} seconds</span>
            </div>
            <div class="metric">
                <strong>Total Packets:</strong> <span class="metric-value">{results.packet_count:,}</span>
            </div>
        </div>

        {'<div class="threat-detected"><h3>⚠️ Threats Detected</h3><ul>' + ''.join([f'<li>{threat}</li>' for threat in threat_summary]) + '</ul></div>' if threat_summary else '<div class="no-threats"><h3>✅ No Threats Detected</h3></div>'}

        <h2>Protocol Distribution</h2>
        <div class="protocol-stats">
"""
    
    for proto, count in results.protocol_distribution.items():
        percentage = _calculate_percentage(count, results.packet_count)
        html_content += f"""
            <div class="protocol-card">
                <h3>{proto}</h3>
                <div class="metric-value">{count:,}</div>
                <div>({percentage:.1f}%)</div>
            </div>
"""
    
    html_content += """
        </div>

        <h2>Top Conversations</h2>
        <table>
            <thead>
                <tr>
                    <th>Conversation</th>
                    <th>Packets</th>
                    <th>Percentage</th>
                </tr>
            </thead>
            <tbody>
"""
    
    for conv, count in results.top_talkers[:10]:
        percentage = _calculate_percentage(count, results.packet_count)
        html_content += f"""
                <tr>
                    <td>{conv}</td>
                    <td>{count:,}</td>
                    <td>{percentage:.1f}%</td>
                </tr>
"""
    
    html_content += f"""
            </tbody>
        </table>

        <h2>HTTP Analysis</h2>
        <div class="metric">
            <strong>Total HTTP Requests:</strong> <span class="metric-value">{results.http_analysis.total_http_requests:,}</span>
        </div>

        <h2>TLS Analysis</h2>
        <div class="metric">
            <strong>Total TLS Sessions:</strong> <span class="metric-value">{results.tls_analysis.total_tls_sessions:,}</span>
        </div>
        
        <h3>TLS Versions</h3>
        <table>
            <thead>
                <tr>
                    <th>Version</th>
                    <th>Count</th>
                </tr>
            </thead>
            <tbody>
"""
    
    formatted_versions = _format_tls_versions(results.tls_analysis.tls_versions)
    for version, count in formatted_versions.items():
        html_content += f"""
                <tr>
                    <td>{version}</td>
                    <td>{count}</td>
                </tr>
"""
    
    html_content += """
            </tbody>
        </table>
    </div>
</body>
</html>
"""
    
    return html_content