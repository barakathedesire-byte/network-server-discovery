import socket
from typing import Dict, List, Optional, Set


def resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def reverse_dns_lookup(ip: str) -> Optional[str]:
    """Perform reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.error):
        return None


def dns_enumerate(domain: str, timeout: float = 2.0) -> List[Dict[str, str]]:
    """Enumerate DNS records for a domain."""
    results = []
    common_subdomains = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns", "admin",
        "test", "portal", "api", "dev", "staging", "prod", "vpn", "proxy", "git",
        "jenkins", "docker", "app", "db", "cdn", "storage", "backup",
    ]

    for subdomain in common_subdomains:
        hostname = f"{subdomain}.{domain}"
        try:
            ip = socket.gethostbyname(hostname)
            results.append({"hostname": hostname, "ip": ip})
        except socket.gaierror:
            pass

    return results


def get_all_ips_for_hostname(hostname: str) -> Set[str]:
    """Get all IP addresses for a hostname."""
    ips: Set[str] = set()
    try:
        for info in socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
            ips.add(info[4][0])
    except socket.gaierror:
        pass
    return ips


def is_private_ip(ip: str) -> bool:
    """Check if an IP is private,"""
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4:
            return False
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        if parts[0] == 169 and parts[1] == 254:
            return True
        return False
    except (ValueError, IndexError):
        return False
