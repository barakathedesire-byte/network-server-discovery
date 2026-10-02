import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import socket
from datetime import datetime, timezone
from typing import Iterable, List, Optional

from .models import HostInfo, ScanResult, ServiceInfo


DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000]


def _service_name_for_port(port: int) -> str:
    mapping = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        111: "RPCbind",
        135: "RPC",
        139: "SMB",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        993: "IMAPS",
        995: "POP3S",
        1433: "MSSQL",
        1521: "Oracle",
        1723: "PPTP",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        9000: "Custom",
    }
    return mapping.get(port, f"Port-{port}")


def _resolve_target(target: str) -> List[str]:
    value = target.strip()
    if not value:
        raise ValueError("Target cannot be empty")

    try:
        ip_obj = ipaddress.ip_address(value)
        return [str(ip_obj)]
    except ValueError:
        pass

    try:
        network = ipaddress.ip_network(value, strict=False)
        return [str(ip) for ip in network.hosts()] if network.num_addresses > 1 else [str(network.network_address)]
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(value, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target {value!r}") from exc

    ips = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise ValueError(f"No IPs resolved for {value!r}")
    return ips


def _read_banner(sock: socket.socket, timeout: float) -> str:
    sock.settimeout(timeout)
    try:
        sock.sendall(b"\n")
    except OSError:
        pass

    try:
        data = sock.recv(1024)
        if not data:
            return ""
        return data.decode("utf-8", errors="replace").strip()
    except socket.timeout:
        return ""
    except OSError:
        return ""


class NetworkScanner:
    def __init__(
        self,
        target: str,
        ports: Optional[Iterable[int]] = None,
        timeout: float = 1.5,
        threads: int = 20,
        mode: str = "network",
    ) -> None:
        self.target = target
        self.ports = list(ports) if ports is not None else DEFAULT_PORTS
        self.timeout = timeout
        self.threads = max(1, threads)
        self.mode = mode

    def _scan_host(self, ip: str) -> HostInfo:
        hostname: Optional[str] = None
        services: List[ServiceInfo] = []
        open_ports: List[int] = []

        try:
            hostname = socket.getfqdn(ip)
        except OSError:
            hostname = None

        for port in self.ports:
            try:
                with socket.create_connection((ip, port), self.timeout) as sock:
                    banner = _read_banner(sock, self.timeout)
                    service = ServiceInfo(
                        name=_service_name_for_port(port),
                        port=port,
                        protocol="tcp",
                        status="open",
                        banner=banner,
                    )
                    services.append(service)
                    open_ports.append(port)
            except (OSError, socket.timeout):
                continue

        return HostInfo(
            ip=ip,
            hostname=hostname,
            alive=bool(open_ports),
            open_ports=open_ports,
            services=services,
        )

    def scan(self) -> ScanResult:
        targets = _resolve_target(self.target)

        hosts: List[HostInfo] = []
        with ThreadPoolExecutor(max_workers=min(self.threads, max(1, len(targets)))) as executor:
            futures = {executor.submit(self._scan_host, ip): ip for ip in targets}
            for future in as_completed(futures):
                host = future.result()
                if host.alive or self.mode == "host":
                    hosts.append(host)

        sorted_hosts = sorted(hosts, key=lambda h: [int(part) for part in h.ip.split(".")])
        return ScanResult(
            target=self.target,
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            hosts=sorted_hosts,
        )

    def export_json(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(self.scan().to_dict(), handle, indent=2)

    def export_html(self) -> str:
        result = self.scan()
        rows = []
        for host in result.hosts:
            if not host.services:
                continue
            service_html = "<br>".join(
                f"{service.name} ({service.port}){': ' + service.banner if service.banner else ''}" for service in host.services
            )
            rows.append(
                f"<tr><td>{host.ip}</td><td>{host.hostname or 'unknown'}</td><td>{service_html}</td></tr>"
            )

        body = "\n".join(rows) if rows else "<tr><td colspan='3'>No hosts discovered</td></tr>"
        return f"""
        <html>
          <head>
            <title>Network Server Discovery Report</title>
            <style>
              body {{ font-family: Arial, sans-serif; padding: 30px; }}
              table {{ border-collapse: collapse; width: 100%; }}
              th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
              th {{ background: #f2f2f2; }}
            </style>
          </head>
          <body>
            <h1>Network Server Discovery Report</h1>
            <p>Target: {result.target}</p>
            <table>
              <thead>
                <tr><th>IP</th><th>Hostname</th><th>Services</th></tr>
              </thead>
              <tbody>
                {body}
              </tbody>
            </table>
          </body>
        </html>
        """
