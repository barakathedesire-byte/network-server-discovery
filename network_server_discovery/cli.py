import argparse
import json
from pathlib import Path

from .advanced_scanner import AdvancedNetworkScanner


def _parse_ports(raw: str):
    if not raw:
        return None
    ports = []
    for value in raw.split(","):
        item = value.strip()
        if not item:
            continue
        port = int(item)
        if not 1 <= port <= 65535:
            raise ValueError(f"Port out of range: {port}")
        ports.append(port)
    return ports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nsd",
        description="Authorized network server discovery and virtual host inventory tool",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover = subparsers.add_parser("discover", help="Scan a target network or host")
    discover.add_argument("target", help="Target IP, hostname, or CIDR range")
    discover.add_argument("--ports", default="", help="Comma-separated ports to scan")
    discover.add_argument("--timeout", type=float, default=1.5, help="Socket timeout in seconds")
    discover.add_argument("--threads", type=int, default=20, help="Maximum threads")
    discover.add_argument("--vhost-scan", action="store_true", help="Enumerate HTTP virtual hosts")
    discover.add_argument("--dns-enum", action="store_true", help="Enumerate common DNS records")
    discover.add_argument("--mode", choices=["network", "host"], default="network")
    discover.add_argument("--output", help="Write output to file")
    discover.add_argument("--format", choices=["json", "html"], default="json", help="Output file format")
    discover.add_argument("--verbose", action="store_true", help="Print verbose scan output")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        ports = _parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    scanner = AdvancedNetworkScanner(
        target=args.target,
        ports=ports,
        timeout=args.timeout,
        threads=args.threads,
        mode=args.mode,
        vhost_scan=args.vhost_scan,
        dns_enum=args.dns_enum,
    )
    result = scanner.scan()

    if args.verbose:
        print(f"Target: {result.target}")
        print(f"Hosts discovered: {len(result.hosts)}")
        for host in result.hosts:
            print(f"{host.ip} ({host.hostname or 'unknown'}): {host.open_ports}")

    payload = result.to_dict()

    if args.output:
        out_path = Path(args.output)
        if args.format == "json":
            out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        else:
            out_path.write_text(
                "<html><body><pre>" + __import__('html').escape(json.dumps(payload, indent=2)) + "</pre></body></html>",
                encoding="utf-8",
            )
        print(f"Results written to {out_path}")
    else:
        print(json.dumps(payload, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
