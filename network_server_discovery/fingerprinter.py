import re
import socket
from typing import Dict, List, Tuple


class BannerFingerprinter:
    """Fingerprint services based on banners and common port signatures."""

    SERVICE_SIGNATURES = {
        "SSH": {"ports": [22, 2222, 2223], "patterns": [r"SSH-.*"]},
        "HTTP": {"ports": [80, 8080, 8000, 8888, 3128], "patterns": [r"HTTP/", r"Server:", r"<html"]},
        "HTTPS": {"ports": [443, 8443, 8445], "patterns": [r"SSL", r"TLS", r"X-Frame-Options"]},
        "FTP": {"ports": [21, 2121], "patterns": [r"^220", r"FTP"]},
        "SMTP": {"ports": [25, 587, 465], "patterns": [r"^220", r"SMTP"]},
        "POP3": {"ports": [110, 995], "patterns": [r"\+OK", r"POP3"]},
        "IMAP": {"ports": [143, 993], "patterns": [r"\* OK", r"IMAP"]},
        "MySQL": {"ports": [3306, 3307], "patterns": [r"mysql", r"MySQL"]},
        "PostgreSQL": {"ports": [5432], "patterns": [r"postgres", r"PostgreSQL"]},
        "MongoDB": {"ports": [27017, 27018, 27019], "patterns": [r"mongo", r"MongoDB"]},
        "Redis": {"ports": [6379], "patterns": [r"redis", r"Redis", r"\$\d+"]},
        "Elasticsearch": {"ports": [9200, 9300], "patterns": [r"elasticsearch", r"Elastic"]},
        "Docker": {"ports": [2375, 2376], "patterns": [r"docker", r"Docker"]},
        "RDP": {"ports": [3389], "patterns": [r"RDP", r"Terminal"]},
        "VNC": {"ports": [5900, 5901, 5902], "patterns": [r"RFB", r"VNC"]},
        "SMB": {"ports": [139, 445], "patterns": [r"SMB", r"samba"]},
    }

    @classmethod
    def fingerprint_banner(cls, port: int, banner: str) -> Tuple[str, float]:
        banner_lower = banner.lower()
        if not banner:
            return "Unknown", 0.0

        scores: Dict[str, float] = {}
        for service, cfg in cls.SERVICE_SIGNATURES.items():
            score = 0.0
            if port in cfg["ports"]:
                score += 0.4
            for pattern in cfg["patterns"]:
                if re.search(pattern, banner, re.IGNORECASE):
                    score += 0.6
            if score > 0:
                scores[service] = score

        if not scores:
            return "Unknown", 0.0

        best_service = max(scores, key=scores.get)
        return best_service, min(scores[best_service], 1.0)

    @classmethod
    def probe_service(cls, sock: socket.socket, port: int, timeout: float) -> str:
        """Send a minimal probe and collect the banner."""
        sock.settimeout(timeout)
        payload_map = {
            22: b"\n",
            25: b"EHLO test\r\n",
            80: b"HEAD / HTTP/1.0\r\n\r\n",
            443: b"\x16\x03\x01\x00",
            3306: b"\n",
            5432: b"\n",
            6379: b"PING\r\n",
            9200: b"GET / HTTP/1.0\r\n\r\n",
        }

        payload = payload_map.get(port, b"\n")
        try:
            sock.sendall(payload)
            data = sock.recv(4096)
            if data:
                return data.decode("utf-8", errors="replace").strip()
        except (socket.timeout, OSError):
            return ""
        return ""


class VirtualHostDiscovery:
    """Enumerate likely virtual hosts on HTTP/HTTPS services."""

    COMMON_VHOSTS = [
        "localhost", "www", "mail", "api", "admin", "portal", "app",
        "dev", "staging", "prod", "cdn", "static", "db", "ftp",
    ]

    @classmethod
    def discover_vhosts(cls, ip: str, port: int, hostname: str | None = None, timeout: float = 2.0) -> List[Dict[str, str]]:
        candidates = set(cls.COMMON_VHOSTS)
        if hostname:
            candidates.add(hostname)
            domain = ".".join(hostname.split(".")[1:]) if "." in hostname else hostname
            if domain:
                for v in cls.COMMON_VHOSTS:
                    candidates.add(f"{v}.{domain}")
        
        results: List[Dict[str, str]] = []
        protocol = "https" if port in (443, 8443, 8445) else "http"

        for candidate in sorted(candidates):
            try:
                sock = socket.create_connection((ip, port), timeout=timeout)
                req = (
                    f"HEAD / HTTP/1.1\r\n"
                    f"Host: {candidate}\r\n"
                    "Connection: close\r\n\r\n"
                ).encode("utf-8")
                sock.sendall(req)
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                sock.close()

                body = response.decode("utf-8", errors="replace")
                if "HTTP/" in body and "200" in body.split("\n", 1)[0]:
                    results.append({
                        "vhost": candidate,
                        "ip": ip,
                        "port": str(port),
                        "protocol": protocol,
                        "status": "responsive",
                    })
            except (socket.timeout, OSError):
                continue

        return results
