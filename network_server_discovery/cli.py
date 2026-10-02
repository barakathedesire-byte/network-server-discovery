import argparse
import json
from pathlib import Path

from .scanner import NetworkScanner


DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nsd", description="Authorized network server discovery and inventory tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover = subparsers.add_parser("discover", help="Scan a target network or host")
    discover.add_argument("target", help="Target IP, hostname, or CIDR range")
    discover.add_argument("--ports", default=",".join(str(p) for p in DEFAULT_PORTS), help="Comma-separated list of ports to probe")
    discover.add_argument("--timeout", type=float, default=1.5, help="Socket timeout in seconds")
    discover.add_argument("--threads", type=int, default=20, help="Max concurrent probes")
    discover.add_argument("--speed", choices=["slow", "normal", "fast"], default="normal", help="Scan speed profile")
    discover.add_argument("--output", help="Write results to a file")
    discover.add_argument("--format", choices=["json", "html"], default="json", help="Output format for exported results")
    discover.add_argument("--mode", choices=["network", "host"], default="network", help="Discovery mode")
    discover.add_argument("--verbose", action="store_true", help="Print verbose progress")

    return parser


def _parse_ports(raw: str):
    ports = []
    for value in raw.split(","):
        item = value.strip()
        if not item:
            continue
        try:
            port = int(item)
        except ValueError as exc:
            raise ValueError(f"Invalid port value: {item!r}") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"Port out of range: {port}")
        ports.append(port)
    if not ports:
        raise ValueError("No valid ports were supplied")
    return ports


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        ports = _parse_ports(args.ports)
    except ValueError as exc:
        parser.error(str(exc))

    speed_map = {
        "slow": {"timeout": 2.5, "threads": min(10, args.threads)},
        "normal": {"timeout": 1.5, "threads": args.threads},
        "fast": {"timeout": 1.0, "threads": max(args.threads, 25)},
    }
    speed_cfg = speed_map[args.speed]

    scanner = NetworkScanner(
        target=args.target,
        ports=ports,
        timeout=speed_cfg["timeout"],
        threads=speed_cfg["threads"],
        mode=args.mode,
    )

    result = scanner.scan()

    if args.verbose:
        print(f"Target: {result.target}")
        print(f"Hosts discovered: {len(result.hosts)}")
        for host in result.hosts:
            if host.open_ports:
                print(f"{host.ip} ({host.hostname or 'unknown'}): {host.open_ports}")

    if args.output:
        output_path = Path(args.output)
        if args.format == "json":
            output_path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
        else:
            output_path.write_text(scanner.export_html(), encoding="utf-8")
        print(f"Results written to {output_path}")
    else:
        print(json.dumps(result.to_dict(), indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
