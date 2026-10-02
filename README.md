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
- JSON export and web dashboard UI
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
nsd discover 192.168.1.0/24 --ports 22,80,443,3306 --threads 25
nsd discover example.com --vhost-scan --dns-enum
nsd discover 10.0.0.0/24 --output results.json
```

### Web UI

```bash
nsd-web
```

Then open http://localhost:5000

## Example API usage

```python
from network_server_discovery.advanced_scanner import AdvancedNetworkScanner

scanner = AdvancedNetworkScanner(
    target="example.com",
    ports=[80, 443, 8080],
    timeout=1.5,
    threads=20,
    vhost_scan=True,
    dns_enum=True,
)

result = scanner.scan()
print(result.summary())
print(result.to_dict())
```

## Legal and Ethical Use

This tool is intended for authorized network inventory, internal infrastructure discovery, and permitted security assessment work only. Do not use it against any network or system unless you have explicit written permission.

## License

MIT
