#!/usr/bin/env python3
"""
PcapSleuth CLI - Command Line Interface
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
              default='text', help='Output format')
@click.option('--dns-entropy-threshold', type=float, default=3.5,
              help='DNS entropy threshold for tunneling detection')
@click.option('--icmp-flood-threshold', type=int, default=100,
              help='ICMP packet threshold for flood detection')
@click.option('--quiet', '-q', is_flag=True, help='Suppress progress bar')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
def analyze(pcap_file, output, format, dns_entropy_threshold, icmp_flood_threshold, quiet, verbose):
    """Analyze a PCAP file for network threats and statistics."""
    
    print_banner() # <<< Show banner before anything else
    
    # Configure logging level
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif quiet:
        logging.getLogger().setLevel(logging.WARNING)
    
    try:
        # Create configuration
        config = Config(
            dns_entropy_threshold=dns_entropy_threshold,
            icmp_flood_threshold=icmp_flood_threshold,
            show_progress=not quiet
        )
        
        # Initialize engine
        engine = PcapAnalysisEngine(config)
        
        # Analyze PCAP
        click.echo(f"Analyzing PCAP file: {pcap_file}")
        results = engine.analyze_pcap(pcap_file)
        
        # Generate report
        report = generate_report(results, format)
        
        # Output results
        if output:
            with open(output, 'w') as f:
                f.write(report)
            click.echo(f"Report saved to: {output}")
        else:
            click.echo(report)
        
        # Show summary
        click.echo(f"\nAnalysis complete!")
        click.echo(f"Processed {results.packet_count:,} packets")
        
        if results.errors:
            click.echo(f"Warnings: {len(results.errors)} errors encountered")
            if verbose:
                for error in results.errors:
                    click.echo(f"  - {error}")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

if __name__ == '__main__':
    analyze()