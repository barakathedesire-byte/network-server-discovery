"""Advanced scanning capabilities for network server discovery."""

import asyncio
import socket
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Result of a network scan."""
    host: str
    port: int
    is_open: bool
    service: Optional[str] = None
    version: Optional[str] = None
    response_time: float = 0.0
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


class AdvancedScanner:
    """Advanced network scanner with multiple techniques."""

    def __init__(self, timeout: int = 5, max_workers: int = 50):
        self.timeout = timeout
        self.max_workers = max_workers
        self.common_ports = {
            22: 'ssh',
            80: 'http',
            443: 'https',
            3306: 'mysql',
            5432: 'postgresql',
            6379: 'redis',
            27017: 'mongodb',
            8080: 'http-alt',
            8443: 'https-alt',
        }

    async def scan_host(self, host: str, ports: Optional[List[int]] = None) -> List[ScanResult]:
        """Scan a host for open ports."""
        if ports is None:
            ports = list(self.common_ports.keys())

        tasks = [self._check_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    async def _check_port(self, host: str, port: int) -> Optional[ScanResult]:
        """Check if a port is open."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.timeout
            )
            service = self.common_ports.get(port, 'unknown')
            writer.close()
            await writer.wait_closed()
            return ScanResult(host=host, port=port, is_open=True, service=service)
        except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
            return ScanResult(host=host, port=port, is_open=False)

    def scan_network(self, network: str) -> List[ScanResult]:
        """Scan a network range for active hosts."""
        # Parse CIDR notation
        import ipaddress
        net = ipaddress.ip_network(network, strict=False)
        results = []
        
        for ip in list(net.hosts())[:255]:  # Limit to reasonable number
            try:
                result = asyncio.run(self._check_host(str(ip)))
                if result:
                    results.append(result)
            except Exception as e:
                logger.debug(f"Error scanning {ip}: {e}")
        
        return results

    async def _check_host(self, host: str) -> Optional[ScanResult]:
        """Check if a host is alive."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 80),
                timeout=1
            )
            writer.close()
            await writer.wait_closed()
            return ScanResult(host=host, port=80, is_open=True)
        except Exception:
            return None
