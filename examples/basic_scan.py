import socket
from typing import Iterable, List


def parse_ports(raw_ports: str) -> List[int]:
    parsed = []
    for value in raw_ports.split(","):
        item = value.strip()
        if not item:
            continue
        port = int(item)
        if not 1 <= port <= 65535:
            raise ValueError(f"Port out of range: {port}")
        parsed.append(port)
    if not parsed:
        raise ValueError("No valid ports were supplied")
    return parsed


def banner_from_socket(sock: socket.socket, timeout: float) -> str:
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\n")
        data = sock.recv(1024)
        if data:
            return data.decode("utf-8", errors="replace").strip()
    except (OSError, socket.timeout):
        return ""
    return ""
