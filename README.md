# pcapsleuth
PcapSleuth is a fast, modular DFIR toolkit for automated PCAP traffic analysis. It provides a clean CLI, threat detection (DNS tunneling, ICMP floods, port scans), and rich reporting (text, JSON, Markdown, HTML).

## Key Features
- **Modular analyzers**: `BasicStats`, `DNS`, `ICMP`, `Port Scan`, optional `HTTP`, optional `TLS`
- **Threat detection**: DNS tunneling heuristics, ICMP flood indicators, TCP/UDP/stealth/rapid scans
- **Clear CLI**: Sensible defaults, verbose/quiet modes, batch processing, progress bar
- **Rich reports**: Text, JSON, Markdown, and styled HTML via `pcapsleuth/reporting.py`
- **Performance-aware**: Batched packet processing, adjustable batch size, tqdm progress

## Install
Prereqs: Python 3.8–3.11, libpcap (platform-provided), and pip.

Option A – local (recommended during development):
```bash
python -m venv .venv && . .venv/Scripts/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Option B – editable install:
```bash
pip install -e .
```

This exposes the console script `pcapsleuth` (see `setup.py`).

## Quick Start
Analyze a capture with default analyzers and text output:
```bash
pcapsleuth path/to/capture.pcap
# or
python main.py path/to/capture.pcap
```

Save a JSON report:
```bash
pcapsleuth capture.pcap -f json -o report.json
```

Enable TLS and HTML reporting:
```bash
pcapsleuth capture.pcap --enable-tls -f html -o report.html
```

Quiet mode with Markdown output:
```bash
pcapsleuth capture.pcap -q -f markdown -o report.md
```

## CLI Usage
The CLI is defined in `main.py` (entry: `analyze`). Key options:

- **Output**: `--format [text|json|markdown|html]`, `--output PATH`
- **DNS**: `--dns-entropy-threshold`, `--dns-max-query-length`, `--dns-txt-threshold`
- **ICMP**: `--icmp-flood-threshold`, `--icmp-flood-window`
- **Port scan**: `--syn-scan-threshold`, `--udp-scan-threshold`, `--stealth-scan-threshold`, `--rapid-scan-threshold`, `--rapid-scan-window`
- **HTTP/TLS**: `--http-enabled/--no-http-enabled`, `--enable-tls`
- **General**: `--batch-size`, `--max-top-talkers`, `--max-dns-queries`, `--quiet/-q`, `--verbose/-v`, `--no-banner`, `--show-errors`

Show help:
```bash
pcapsleuth --help
```

## What It Detects
- **DNS Tunneling**: High-entropy queries, excessive TXT usage, long labels
- **ICMP Floods**: Volume over time windows
- **Port Scanning**: TCP SYN, UDP, stealth patterns, rapid scan bursts
- **HTTP** (optional): Request counts, methods, hostnames, URLs
- **TLS** (optional): Session counts, versions, SNI/certificate hosts

Results are aggregated into `pcapsleuth/models.py:AnalysisResult` and rendered by `pcapsleuth/reporting.py`.

## Reports
Implemented in `pcapsleuth/reporting.py`:
- **text**: Console-friendly summary with threat overview
- **json**: Machine-readable structure (metadata, stats, threats, errors)
- **markdown**: Tables for protocol distribution, DNS, HTTP, TLS
- **html**: Styled, lightweight single-file report

## Project Structure
```
pcapsleuth/
├─ main.py                  # CLI
├─ pcapsleuth/
│  ├─ core.py               # Analysis engine (batching, progress, finalization)
│  ├─ models.py             # Config, ProcessingState, AnalysisResult (+ HTTP/TLS)
│  ├─ reporting.py          # text/json/markdown/html generators
│  └─ analysis/
│     ├─ basic_stats.py     # Top talkers, protocols, DNS counts, etc.
│     ├─ dns_analyzer.py    # Entropy, TXT thresholds, tunneling heuristics
│     ├─ icmp_analyzer.py   # Flood indicators
│     ├─ port_scan_analyzer.py # SYN/UDP/stealth/rapid scans, open ports
│     ├─ http_analyzer.py   # Optional HTTP insights (enabled by flag)
│     └─ tls_analyzer.py    # Optional TLS insights (enabled by flag)
└─ requirements.txt
```

## Requirements
See `requirements.txt` for exact pins. Core libraries include:
- `scapy` (PCAP parsing)
- `click`, `tqdm`, `colorama` (CLI + progress)
- Optional: `streamlit` (future web UI)

Python: 3.8–3.11 (see `setup.py`).

## Development
```bash
git clone https://github.com/KibnD/pcapsleuth.git
cd pcapsleuth
python -m venv .venv && . .venv/Scripts/activate  # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -e .[dev]
pytest -q
```

Useful scripts in `scripts/`: generate test pcaps, simple smoke tests.

## Troubleshooting
- If TLS analysis prints cipher suite warnings, use `--enable-tls` only when needed; output rendering already filters common noise. Use `-q` to suppress logs.
- Large PCAPs: increase `--batch-size` and keep progress enabled for feedback.
- Empty or invalid PCAPs are rejected early by `PcapAnalysisEngine._validate_pcap_file()`.

## Roadmap
- Expand analyzer coverage (HTTP/TLS depth, DoH/QUIC hints)
- Enhanced visual reporting and correlations
- Broader test coverage and sample datasets

## License
MIT License. See `LICENSE`.

## Acknowledgments
Built with Scapy and the Python networking community.
