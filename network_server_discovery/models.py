from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class ServiceInfo:
    name: str
    port: int
    protocol: str = "tcp"
    status: str = "open"
    banner: str = ""
    confidence: float = 0.5

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "port": self.port,
            "protocol": self.protocol,
            "status": self.status,
            "banner": self.banner,
            "confidence": round(self.confidence, 2),
        }


@dataclass
class VHostInfo:
    vhost: str
    ip: str
    port: int
    protocol: str = "http"
    status: str = "responsive"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vhost": self.vhost,
            "ip": self.ip,
            "port": self.port,
            "protocol": self.protocol,
            "status": self.status,
        }


@dataclass
class HostInfo:
    ip: str
    hostname: Optional[str] = None
    alive: bool = True
    open_ports: List[int] = field(default_factory=list)
    services: List[ServiceInfo] = field(default_factory=list)
    vhosts: List[VHostInfo] = field(default_factory=list)
    is_private: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "alive": self.alive,
            "is_private": self.is_private,
            "open_ports": self.open_ports,
            "services": [service.to_dict() for service in self.services],
            "vhosts": [vhost.to_dict() for vhost in self.vhosts],
        }


@dataclass
class ScanResult:
    target: str
    started_at: datetime
    completed_at: datetime
    hosts: List[HostInfo] = field(default_factory=list)
    offline_servers: List[Dict[str, Any]] = field(default_factory=list)
    dns_results: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        duration = (self.completed_at - self.started_at).total_seconds()
        return {
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_seconds": round(duration, 2),
            "hosts_discovered": len(self.hosts),
            "total_services": sum(len(host.services) for host in self.hosts),
            "hosts": [host.to_dict() for host in self.hosts],
            "offline_servers": self.offline_servers,
            "dns_results": self.dns_results,
        }

    def summary(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "hosts_found": len(self.hosts),
            "services_found": sum(len(host.services) for host in self.hosts),
            "vhosts_found": sum(len(host.vhosts) for host in self.hosts),
            "offline_servers_registered": len(self.offline_servers),
            "dns_records_enumerated": len(self.dns_results),
        }
