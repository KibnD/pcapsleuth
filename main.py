#!/usr/bin/env python3
"""
PcapSleuth CLI - Command Line Interface
Enhanced with comprehensive port scanning and analysis options
"""

import click
import logging
import sys
from pathlib import Path

from pcapsleuth import PcapAnalysisEngine, Config
from pcapsleuth.reporting import generate_report

# Load and display ASCII banner
def print_banner():
    try:
        banner_path = Path(__file__).parent / "banner.txt"
        with open(banner_path, 'r', encoding='utf-8') as f:
            banner = f.read()
            click.secho(banner, fg='cyan')  # colored output
    except Exception as e:
        logging.debug(f"Banner could not be displayed: {e}")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

@click.command()
@click.argument('pcap_file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output file path')
@click.option('--format', '-f', type=click.Choice(['text', 'json', 'markdown']), 
              default='text', help='Output format (text, json, markdown)')

# DNS Analysis Options
@click.option('--dns-entropy-threshold', type=float, default=3.5,
              help='DNS entropy threshold for tunneling detection (default: 3.5)')
@click.option('--dns-max-query-length', type=int, default=100,
              help='Maximum DNS query length before flagging (default: 100)')
@click.option('--dns-txt-threshold', type=int, default=50,
              help='TXT query threshold for excessive queries detection (default: 50)')

# ICMP Analysis Options
@click.option('--icmp-flood-threshold', type=int, default=100,
              help='ICMP packet threshold for flood detection (default: 100)')
@click.option('--icmp-flood-window', type=int, default=1,
              help='Time window in seconds for ICMP flood detection (default: 1)')

# Port Scanning Analysis Options
@click.option('--syn-scan-threshold', type=int, default=20,
              help='Minimum unique ports to consider TCP SYN scan (default: 20)')
@click.option('--udp-scan-threshold', type=int, default=15,
              help='Minimum unique ports to consider UDP scan (default: 15)')
@click.option('--stealth-scan-threshold', type=int, default=10,
              help='Minimum attempts to consider stealth scan (default: 10)')
@click.option('--rapid-scan-threshold', type=int, default=50,
              help='Packets per second threshold for rapid scan detection (default: 50)')
@click.option('--rapid-scan-window', type=int, default=1,
              help='Time window in seconds for rapid scan detection (default: 1)')

# Display Options
@click.option('--max-top-talkers', type=int, default=10,
              help='Maximum number of top talkers to display (default: 10)')
@click.option('--max-dns-queries', type=int, default=10,
              help='Maximum number of DNS queries to display (default: 10)')
@click.option('--batch-size', type=int, default=1000,
              help='Packet processing batch size (default: 1000)')

# General Options
@click.option('--quiet', '-q', is_flag=True, help='Suppress progress bar and reduce output')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging and detailed output')
@click.option('--no-banner', is_flag=True, help='Suppress ASCII banner display')
@click.option('--show-errors', is_flag=True, help='Display detailed error information')

def analyze(pcap_file, output, format, dns_entropy_threshold, dns_max_query_length, 
           dns_txt_threshold, icmp_flood_threshold, icmp_flood_window,
           syn_scan_threshold, udp_scan_threshold, stealth_scan_threshold,
           rapid_scan_threshold, rapid_scan_window, max_top_talkers, max_dns_queries,
           batch_size, quiet, verbose, no_banner, show_errors):
    """
    Analyze a PCAP file for network threats and statistics.
    
    PCAP_FILE: Path to the PCAP file to analyze
    
    Examples:
    \b
        # Basic analysis
        python main.py capture.pcap
        
        # Save JSON report with custom thresholds
        python main.py capture.pcap -o report.json -f json --syn-scan-threshold 10
        
        # Verbose analysis with custom DNS settings
        python main.py capture.pcap -v --dns-entropy-threshold 4.0 --dns-txt-threshold 30
        
        # Quiet mode with markdown output
        python main.py capture.pcap -q -f markdown -o report.md
    """
    
    # Show banner unless suppressed
    if not no_banner:
        print_banner()
    
    # Configure logging level
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif quiet:
        logging.getLogger().setLevel(logging.WARNING)
    
    try:
        # Create comprehensive configuration
        config = Config(
            # DNS Analysis Settings
            dns_entropy_threshold=dns_entropy_threshold,
            dns_max_query_length=dns_max_query_length,
            dns_txt_query_threshold=dns_txt_threshold,
            
            # ICMP Analysis Settings
            icmp_flood_threshold=icmp_flood_threshold,
            icmp_flood_time_window=icmp_flood_window,
            
            # Port Scanning Analysis Settings
            syn_scan_threshold=syn_scan_threshold,
            udp_scan_threshold=udp_scan_threshold,
            stealth_scan_threshold=stealth_scan_threshold,
            rapid_scan_threshold=rapid_scan_threshold,
            rapid_scan_window=rapid_scan_window,
            
            # General Settings
            max_top_talkers=max_top_talkers,
            max_dns_queries=max_dns_queries,
            batch_size=batch_size,
            show_progress=not quiet
        )
        
        # Initialize engine
        engine = PcapAnalysisEngine(config)
        
        # Analyze PCAP
        if not quiet:
            click.echo(f"Analyzing PCAP file: {pcap_file}")
            click.echo(f"Configuration:")
            click.echo(f"  DNS entropy threshold: {dns_entropy_threshold}")
            click.echo(f"  ICMP flood threshold: {icmp_flood_threshold}")
            click.echo(f"  SYN scan threshold: {syn_scan_threshold}")
            click.echo(f"  UDP scan threshold: {udp_scan_threshold}")
            click.echo("")
        
        results = engine.analyze_pcap(pcap_file)
        
        # Generate report
        report = generate_report(results, format)
        
        # Output results
        if output:
            output_path = Path(output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(report)
            click.echo(f"Report saved to: {output}")
        else:
            click.echo(report)
        
        # Show enhanced summary
        if not quiet:
            click.echo(f"\n{'='*50}")
            click.echo(f"ANALYSIS SUMMARY")
            click.echo(f"{'='*50}")
            click.echo(f"Processed packets: {results.packet_count:,}")
            click.echo(f"Analysis duration: {results.analysis_duration:.2f}s")
            
            # Threat summary
            threats_detected = 0
            threat_details = []
            
            if results.dns_tunneling.total_suspicious_queries > 0:
                threats_detected += 1
                threat_details.append(f"DNS Tunneling: {results.dns_tunneling.total_suspicious_queries} suspicious queries")
            
            if results.icmp_floods.potential_floods:
                threats_detected += 1
                threat_details.append(f"ICMP Floods: {len(results.icmp_floods.potential_floods)} detected")
            
            if results.port_scanning.total_scan_attempts > 0:
                threats_detected += 1
                scan_types = []
                if results.port_scanning.tcp_syn_scans:
                    scan_types.append(f"{len(results.port_scanning.tcp_syn_scans)} TCP SYN")
                if results.port_scanning.udp_scans:
                    scan_types.append(f"{len(results.port_scanning.udp_scans)} UDP")
                if results.port_scanning.stealth_scans:
                    scan_types.append(f"{len(results.port_scanning.stealth_scans)} Stealth")
                if results.port_scanning.rapid_scans:
                    scan_types.append(f"{len(results.port_scanning.rapid_scans)} Rapid")
                
                threat_details.append(f"Port Scanning: {', '.join(scan_types)}")
            
            if threats_detected > 0:
                click.secho(f"⚠️  {threats_detected} threat type(s) detected:", fg='red')
                for detail in threat_details:
                    click.secho(f"   • {detail}", fg='yellow')
            else:
                click.secho("✅ No significant threats detected", fg='green')
            
            # Protocol distribution summary
            if results.protocol_distribution:
                click.echo(f"\nProtocol distribution:")
                for proto, count in results.protocol_distribution.items():
                    percentage = (count / results.packet_count) * 100
                    click.echo(f"  {proto}: {count:,} packets ({percentage:.1f}%)")
        
        # Show errors if requested or if verbose
        if results.errors and (show_errors or verbose):
            click.echo(f"\n{'='*50}")
            click.secho(f"ERRORS AND WARNINGS ({len(results.errors)} total):", fg='red')
            click.echo(f"{'='*50}")
            for i, error in enumerate(results.errors, 1):
                click.secho(f"{i:2d}. {error}", fg='red')
        elif results.errors and not quiet:
            click.secho(f"⚠️  {len(results.errors)} warnings encountered (use --show-errors or -v for details)", fg='yellow')
        
        # Exit with appropriate code
        exit_code = 0 if not results.errors else 1
        if not quiet:
            click.echo(f"\nAnalysis complete! Exit code: {exit_code}")
        
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        click.echo("\nAnalysis interrupted by user", err=True)
        sys.exit(130)
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(2)
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    analyze()