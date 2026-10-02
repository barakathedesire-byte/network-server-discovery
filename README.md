# Network Server Discovery

A comprehensive open source tool for discovering and identifying servers operating on local and remote networks, including virtual hosts, DNS-named infrastructure, and off-network inventory tracking.

## Features

- Multi-network discovery for IPs, hostnames, and CIDR ranges
- TCP service scanning with port matching and banner grabbing
- Hostname and reverse DNS lookup
- Service fingerprinting with confidence scoring
- HTTP/HTTPS virtual host discovery
- DNS common-subdomain enumeration
- Off-network server registration and tracking
- Multi-format report export (JSON, HTML, CSV)
- Persistent scan history and retrieval
- Interactive web dashboard UI
- Authorization-first scanning workflow

## Installation

```bash
git clone https://github.com/barakathedesire-byte/network-server-discovery.git
cd network-server-discovery
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

## Quick Start

### CLI

```bash
# Basic scan
nsd discover 192.168.1.0/24 --ports 22,80,443,3306 --threads 25

# Scan with vhost enumeration and DNS
nsd discover example.com --vhost-scan --dns-enum

# Custom output format
nsd discover 10.0.0.0/24 --output results.json --format json
```

### Web UI

```bash
nsd-web
```

Then open http://localhost:5000

Features:
- **Scan Tab**: Configure and run scans, register off-network servers
- **History Tab**: View past scans, export, and delete results
- **Multi-format Export**: JSON, HTML, and CSV report formats
- **Persistent Storage**: Scan history stored in `.scan_history` directory

## Report Export

### HTML Report
Professional formatted reports with summary cards, host tables, and service listings.

```bash
nsd discover example.com --vhost-scan --output report.html --format html
```

### CSV Report
Spreadsheet-compatible format for analysis in Excel or other tools.

```bash
# Export via API
curl 'http://localhost:5000/api/scan/scan_1/export?format=csv' -o results.csv
```

### JSON Report
Structured JSON for integration with other tools and automation.

```bash
nsd discover 192.168.1.0/24 --output results.json
```

## Python API

```python
from network_server_discovery.advanced_scanner import AdvancedNetworkScanner
from network_server_discovery.reporting import ReportGenerator, ScanHistory

# Run a scan
scanner = AdvancedNetworkScanner(
    target="example.com",
    ports=[80, 443, 8080],
    vhost_scan=True,
    dns_enum=True,
)

result = scanner.scan()
print(result.summary())

# Generate reports
data = result.to_dict()
html_report = ReportGenerator.generate_html(data)
csv_report = ReportGenerator.generate_csv(data)

# Save and retrieve from history
history = ScanHistory()
history.save_scan("scan_1", data)
previous_scan = history.get_scan("scan_1")
```

## Scan History

Scans are automatically saved to `.scan_history/` directory. Retrieve any past scan:

```bash
# List all scans
http://localhost:5000/api/history

# Get specific scan
http://localhost:5000/api/scan/scan_1

# Export specific scan
http://localhost:5000/api/scan/scan_1/export?format=html
```

## Supported Services

SSH, FTP, Telnet, SMTP, DNS, HTTP, HTTPS, POP3, IMAP, MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, Docker, RDP, VNC, SMB, and many more.

## Legal and Ethical Use

This tool is intended for:
- ✅ Authorized network inventory and internal infrastructure discovery
- ✅ Permitted security assessment work with written authorization
- ✅ Educational and research purposes with proper consent

Do NOT use this tool:
- ❌ Against networks or systems without explicit permission
- ❌ For unauthorized security testing
- ❌ For malicious network reconnaissance

## License

MIT
