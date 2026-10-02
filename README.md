# Network Server Discovery

A comprehensive open source tool for discovering and identifying servers operating on various network types, including standard networks, isolated networks, and alternative connectivity solutions.

## Features

- Multi-network discovery for IPv4 and IPv6 ranges
- TCP port scanning with configurable timing and concurrency
- Service fingerprinting and banner detection
- Host discovery using ICMP and TCP probing
- JSON and HTML report export
- CLI and Python API
- Safe, authorization-first usage model

## Installation

### Requirements
- Python 3.10+
- pip
- Optional: nmap for advanced probes

### Install from source
```bash
git clone https://github.com/barakathedesire-byte/network-server-discovery.git
cd network-server-discovery
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

## Quick Start

```bash
nsd discover 192.168.1.0/24 --ports 22,80,443,3306
nsd discover 10.0.0.0/24 --speed fast --output results.json
nsd discover example.com --mode host
```

## CLI Usage

```bash
nsd --help
nsd discover --help
```

## Python API

```python
from network_server_discovery import NetworkScanner

scanner = NetworkScanner("192.168.1.0/24", ports=[22, 80, 443])
results = scanner.scan()

for host in results.hosts:
    print(host.ip, host.open_ports)
```

## Project Structure

```text
network_server_discovery/
  __init__.py
  cli.py
  scanner.py
  models.py
  report.py
  utils.py
  __main__.py
examples/
  basic_scan.py
  api_usage.py
pyproject.toml
README.md
LICENSE
```

## Legal & Ethical Use

This project is intended for authorized security testing, internal network inventory, and research with explicit permission.

Do not use it against systems or networks without written authorization.

## License

MIT
