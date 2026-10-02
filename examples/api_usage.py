from network_server_discovery.scanner import NetworkScanner


def main() -> None:
    scanner = NetworkScanner("192.168.1.0/24", ports=[22, 80, 443, 3389], timeout=1.0, threads=10)
    result = scanner.scan()
    for host in result.hosts:
        print(f"{host.ip} -> {host.open_ports}")


if __name__ == "__main__":
    main()
