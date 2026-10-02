import json
import csv
from datetime import datetime
from typing import Any, Dict, List
from pathlib import Path


class ReportGenerator:
    """Generate reports in multiple formats."""

    @staticmethod
    def generate_html(scan_result: Dict[str, Any], title: str = "Network Scan Report") -> str:
        """Generate an HTML report."""
        hosts = scan_result.get("hosts", [])
        summary = {
            "target": scan_result.get("target", "Unknown"),
            "hosts_discovered": scan_result.get("hosts_discovered", 0),
            "total_services": scan_result.get("total_services", 0),
            "duration": scan_result.get("duration_seconds", 0),
            "started": scan_result.get("started_at", "N/A"),
            "completed": scan_result.get("completed_at", "N/A"),
        }

        host_rows = ""
        for host in hosts:
            if not host.get("services"):
                continue
            services_html = "".join([
                f"<li>{svc.get('name')}:{svc.get('port')} ({int(svc.get('confidence', 0) * 100)}%)</li>"
                for svc in host.get("services", [])
            ])
            vhosts_html = "".join([
                f"<li>{v.get('vhost')} ({v.get('protocol')}:{v.get('port')})</li>"
                for v in host.get("vhosts", [])
            ])
            host_rows += f"""
            <tr>
                <td><strong>{host.get('ip')}</strong></td>
                <td>{host.get('hostname', 'N/A')}</td>
                <td>{'Yes' if host.get('alive') else 'No'}</td>
                <td>{', '.join(str(p) for p in host.get('open_ports', []))}</td>
                <td><ul style="margin:0;padding-left:20px;">{services_html}</ul></td>
                <td><ul style="margin:0;padding-left:20px;">{vhosts_html or '<li>None</li>'}</ul></td>
            </tr>
            """

        offline_servers_html = ""
        if scan_result.get("offline_servers"):
            for server in scan_result.get("offline_servers", []):
                offline_servers_html += f"""
                <tr>
                    <td>{server.get('ip')}</td>
                    <td>{server.get('hostname')}</td>
                    <td>{', '.join(server.get('services', []))}</td>
                </tr>
                """

        dns_results_html = ""
        if scan_result.get("dns_results"):
            for dns in scan_result.get("dns_results", []):
                dns_results_html += f"""
                <tr>
                    <td>{dns.get('hostname')}</td>
                    <td>{dns.get('ip')}</td>
                </tr>
                """

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>{title}</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background: #f5f5f5;
                    margin: 0;
                    padding: 20px;
                }}
                .container {{
                    max-width: 1400px;
                    margin: 0 auto;
                    background: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                h1, h2 {{
                    color: #333;
                    border-bottom: 2px solid #007bff;
                    padding-bottom: 10px;
                }}
                .summary-grid {{
                    display: grid;
                    grid-template-columns: repeat(4, 1fr);
                    gap: 15px;
                    margin-bottom: 30px;
                }}
                .summary-card {{
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 6px;
                    border-left: 4px solid #007bff;
                }}
                .summary-card strong {{
                    display: block;
                    color: #666;
                    font-size: 0.9em;
                }}
                .summary-card .value {{
                    font-size: 1.8em;
                    color: #007bff;
                    font-weight: bold;
                    margin-top: 5px;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 30px;
                }}
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border: 1px solid #ddd;
                }}
                th {{
                    background: #007bff;
                    color: white;
                    font-weight: bold;
                }}
                tr:nth-child(even) {{
                    background: #f9f9f9;
                }}
                tr:hover {{
                    background: #f0f0f0;
                }}
                .status-online {{
                    color: #28a745;
                    font-weight: bold;
                }}
                .status-offline {{
                    color: #dc3545;
                    font-weight: bold;
                }}
                ul {{
                    margin: 0;
                    padding-left: 20px;
                }}
                .section {{
                    margin-bottom: 40px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>{title}</h1>
                <div class="summary-grid">
                    <div class="summary-card">
                        <strong>Target</strong>
                        <div class="value">{summary['target']}</div>
                    </div>
                    <div class="summary-card">
                        <strong>Hosts Discovered</strong>
                        <div class="value">{summary['hosts_discovered']}</div>
                    </div>
                    <div class="summary-card">
                        <strong>Services Found</strong>
                        <div class="value">{summary['total_services']}</div>
                    </div>
                    <div class="summary-card">
                        <strong>Duration</strong>
                        <div class="value">{summary['duration']:.2f}s</div>
                    </div>
                </div>

                <div class="section">
                    <p><strong>Scan started:</strong> {summary['started']}</p>
                    <p><strong>Scan completed:</strong> {summary['completed']}</p>
                </div>

                <div class="section">
                    <h2>Discovered Hosts</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Hostname</th>
                                <th>Alive</th>
                                <th>Open Ports</th>
                                <th>Services</th>
                                <th>Virtual Hosts</th>
                            </tr>
                        </thead>
                        <tbody>
                            {host_rows if host_rows else '<tr><td colspan="6" style="text-align:center;">No hosts discovered</td></tr>'}
                        </tbody>
                    </table>
                </div>

                {'<div class="section"><h2>Off-Network Servers</h2><table><thead><tr><th>IP</th><th>Hostname</th><th>Services</th></tr></thead><tbody>' + offline_servers_html + '</tbody></table></div>' if offline_servers_html else ''}

                {'<div class="section"><h2>DNS Enumeration Results</h2><table><thead><tr><th>Hostname</th><th>IP Address</th></tr></thead><tbody>' + dns_results_html + '</tbody></table></div>' if dns_results_html else ''}
            </div>
        </body>
        </html>
        """
        return html

    @staticmethod
    def generate_csv(scan_result: Dict[str, Any]) -> str:
        """Generate a CSV report."""
        output = []
        output.append(["IP Address", "Hostname", "Status", "Port", "Service", "Confidence", "Banner", "Virtual Host"])

        for host in scan_result.get("hosts", []):
            ip = host.get("ip")
            hostname = host.get("hostname", "N/A")
            status = "Online" if host.get("alive") else "Offline"

            if host.get("services"):
                for svc in host.get("services", []):
                    output.append([
                        ip,
                        hostname,
                        status,
                        str(svc.get("port")),
                        svc.get("name"),
                        str(round(svc.get("confidence", 0) * 100)),
                        svc.get("banner", "")[:50],
                        "",
                    ])
            else:
                output.append([ip, hostname, status, "", "", "", "", ""])

            if host.get("vhosts"):
                for vhost in host.get("vhosts", []):
                    output.append([
                        ip,
                        hostname,
                        status,
                        str(vhost.get("port")),
                        "",
                        "",
                        "",
                        vhost.get("vhost"),
                    ])

        csv_buffer = []
        for row in output:
            csv_buffer.append(",".join(f'"{cell}"' for cell in row))
        return "\n".join(csv_buffer)

    @staticmethod
    def generate_json(scan_result: Dict[str, Any]) -> str:
        """Generate a JSON report."""
        return json.dumps(scan_result, indent=2)


class ScanHistory:
    """Manage scan history and persistence."""

    def __init__(self, history_dir: str = ".scan_history"):
        self.history_dir = Path(history_dir)
        self.history_dir.mkdir(exist_ok=True)
        self.history_file = self.history_dir / "history.json"

    def save_scan(self, scan_id: str, scan_data: Dict[str, Any]) -> None:
        """Save scan result to disk."""
        scan_file = self.history_dir / f"{scan_id}.json"
        scan_file.write_text(json.dumps(scan_data, indent=2), encoding="utf-8")
        self._update_history_index(scan_id, scan_data)

    def _update_history_index(self, scan_id: str, scan_data: Dict[str, Any]) -> None:
        """Update the history index file."""
        history = self._load_history_index()
        history[scan_id] = {
            "target": scan_data.get("target"),
            "started_at": scan_data.get("started_at"),
            "completed_at": scan_data.get("completed_at"),
            "hosts_discovered": scan_data.get("hosts_discovered", 0),
            "duration_seconds": scan_data.get("duration_seconds", 0),
        }
        self.history_file.write_text(json.dumps(history, indent=2), encoding="utf-8")

    def _load_history_index(self) -> Dict[str, Any]:
        """Load the history index."""
        if self.history_file.exists():
            return json.loads(self.history_file.read_text(encoding="utf-8"))
        return {}

    def get_history(self) -> Dict[str, Any]:
        """Get all scan history."""
        return self._load_history_index()

    def get_scan(self, scan_id: str) -> Dict[str, Any] | None:
        """Load a specific scan by ID."""
        scan_file = self.history_dir / f"{scan_id}.json"
        if scan_file.exists():
            return json.loads(scan_file.read_text(encoding="utf-8"))
        return None

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan from history."""
        scan_file = self.history_dir / f"{scan_id}.json"
        if scan_file.exists():
            scan_file.unlink()
            history = self._load_history_index()
            if scan_id in history:
                del history[scan_id]
                self.history_file.write_text(json.dumps(history, indent=2), encoding="utf-8")
            return True
        return False
