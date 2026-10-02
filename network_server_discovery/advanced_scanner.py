import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .dns_enum import dns_enumerate, is_private_ip, reverse_dns_lookup
from .fingerprinter import BannerFingerprinter, VirtualHostDiscovery
from .models import HostInfo, ScanResult, ServiceInfo, VHostInfo


class AdvancedNetworkScanner:
    """Advanced network scanner for server discovery, vhost detection, and DNS enumeration."""

    DEFAULT_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1433, 1521, 1723, 3306, 3307, 3389, 5432, 5900, 5901, 6379, 8000,
        8080, 8443, 8445, 8888, 9000, 9200, 27017, 27018, 27019
    ]

    def __init__(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        timeout: float = 1.5,
        threads: int = 20,
        mode: str = "network",
        vhost_scan: bool = False,
        dns_enum: bool = False,
    ) -> None:
        self.target = target
        self.ports = list(ports) if ports else self.DEFAULT_PORTS
        self.timeout = timeout
        self.threads = max(1, int(threads))
        self.mode = mode
        self.vhost_scan = vhost_scan
        self.dns_enum_enabled = dns_enum
        self.offline_servers: List[Dict[str, object]] = []

    def _resolve_targets(self) -> List[str]:
        try:
            return [str(ipaddress.ip_address(self.target))]
        except ValueError:
            pass

        try:
            network = ipaddress.ip_network(self.target, strict=False)
            if network.num_addresses > 1:
                return [str(ip) for ip in network.hosts()]
            return [str(network.network_address)]
        except ValueError:
            pass

        try:
            infos = socket.getaddrinfo(self.target, None, proto=socket.IPPROTO_TCP)
            ips = []
            for info in infos:
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
            return ips
        except socket.gaierror as exc:
            raise ValueError(f"Could not resolve target: {self.target}") from exc

    def _scan_host(self, ip: str) -> HostInfo:
        hostname = None
        try:
            hostname = socket.getfqdn(ip)
        except OSError:
            pass

        if not hostname or hostname == ip:
            reverse = reverse_dns_lookup(ip)
            if reverse:
                hostname = reverse

        services: List[ServiceInfo] = []
        open_ports: List[int] = []
        vhosts: List[VHostInfo] = []

        for port in self.ports:
            try:
                with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                    banner = BannerFingerprinter.probe_service(sock, port, self.timeout)
                    service_name, confidence = BannerFingerprinter.fingerprint_banner(port, banner)

                    service = ServiceInfo(
                        name=service_name,
                        port=port,
                        protocol="tcp",
                        status="open",
                        banner=banner,
                        confidence=confidence,
                    )
                    services.append(service)
                    open_ports.append(port)

                    if self.vhost_scan and service_name in {"HTTP", "HTTPS"}:
                        discovered = VirtualHostDiscovery.discover_vhosts(ip, port, hostname, self.timeout)
                        for entry in discovered:
                            vhosts.append(
                                VHostInfo(
                                    vhost=entry["vhost"],
                                    ip=entry["ip"],
                                    port=int(entry["port"]),
                                    protocol=entry["protocol"],
                                    status=entry["status"],
                                )
                            )
            except (OSError, socket.timeout):
                continue

        return HostInfo(
            ip=ip,
            hostname=hostname,
            alive=bool(open_ports),
            open_ports=sorted(open_ports),
            services=services,
            vhosts=vhosts,
            is_private=is_private_ip(ip),
        )

    def add_offline_server(self, ip: str, hostname: str, services: Optional[List[str]] = None) -> None:
        self.offline_servers.append({
            "ip": ip,
            "hostname": hostname,
            "services": services or [],
            "status": "offline",
        })

    def scan(self) -> ScanResult:
        started_at = datetime.now(timezone.utc)
        targets = self._resolve_targets()

        hosts: List[HostInfo] = []
        with ThreadPoolExecutor(max_workers=min(self.threads, max(1, len(targets)))) as executor:
            futures = {executor.submit(self._scan_host, ip): ip for ip in targets}
            for future in as_completed(futures):
                host = future.result()
                if host.alive or self.mode == "host":
                    hosts.append(host)

        hosts = sorted(hosts, key=lambda h: [int(part) for part in h.ip.split(".") if part.isdigit()])

        dns_results = []
        if self.dns_enum_enabled:
            candidate = self.target if "." in self.target else None
            if candidate and not is_private_ip(candidate):
                dns_results = dns_enumerate(candidate)

        return ScanResult(
            target=self.target,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
            hosts=hosts,
            offline_servers=self.offline_servers,
            dns_results=dns_results,
        )
