from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class ServiceInfo:
    name: str
    port: int
    protocol: str = "tcp"
    status: str = "open"
    banner: str = ""

    def to_dict(self):
        return {
            "name": self.name,
            "port": self.port,
            "protocol": self.protocol,
            "status": self.status,
            "banner": self.banner,
        }


@dataclass
class HostInfo:
    ip: str
    hostname: Optional[str] = None
    alive: bool = True
    open_ports: List[int] = field(default_factory=list)
    services: List[ServiceInfo] = field(default_factory=list)

    def to_dict(self):
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "alive": self.alive,
            "open_ports": self.open_ports,
            "services": [service.to_dict() for service in self.services],
        }


@dataclass
class ScanResult:
    target: str
    started_at: datetime
    completed_at: datetime
    hosts: List[HostInfo]

    def to_dict(self):
        return {
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "hosts": [host.to_dict() for host in self.hosts],
        }
