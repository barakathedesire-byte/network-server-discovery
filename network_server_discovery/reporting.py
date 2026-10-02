"""Enhanced reporting and export capabilities."""

import json
import csv
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class Reporter:
    """Generate comprehensive scan reports."""

    def __init__(self, output_dir: str = './reports'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    def generate_json_report(self, scan_data: Dict[str, Any], filename: Optional[str] = None) -> str:
        """Generate JSON report."""
        if filename is None:
            filename = f"scan_report_{self.timestamp}.json"
        
        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            json.dump(scan_data, f, indent=2, default=str)
        
        logger.info(f"JSON report saved to {filepath}")
        return str(filepath)

    def generate_csv_report(self, hosts: List[Dict[str, Any]], filename: Optional[str] = None) -> str:
        """Generate CSV report."""
        if filename is None:
            filename = f"scan_report_{self.timestamp}.csv"
        
        filepath = self.output_dir / filename
        if not hosts:
            logger.warning("No hosts to report")
            return str(filepath)
        
        fieldnames = set()
        for host in hosts:
            fieldnames.update(host.keys())
        fieldnames = sorted(list(fieldnames))
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(hosts)
        
        logger.info(f"CSV report saved to {filepath}")
        return str(filepath)

    def generate_html_report(self, scan_data: Dict[str, Any], filename: Optional[str] = None) -> str:
        """Generate HTML report."""
        if filename is None:
            filename = f"scan_report_{self.timestamp}.html"
        
        filepath = self.output_dir / filename
        html_content = self._build_html_report(scan_data)
        
        with open(filepath, 'w') as f:
            f.write(html_content)
        
        logger.info(f"HTML report saved to {filepath}")
        return str(filepath)

    def _build_html_report(self, scan_data: Dict[str, Any]) -> str:
        """Build HTML report content."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Network Server Discovery Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .summary {{ background-color: #e7f3fe; padding: 10px; margin: 10px 0; }}
    </style>
</head>
<body>
    <h1>Network Server Discovery Report</h1>
    <div class="summary">
        <p><strong>Report Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Total Hosts Scanned:</strong> {len(scan_data.get('hosts', []))}</p>
        <p><strong>Total Open Ports:</strong> {sum(len(h.get('ports', [])) for h in scan_data.get('hosts', []))}</p>
    </div>
    <h2>Scan Results</h2>
    <table>
        <tr>
            <th>Host</th>
            <th>Ports</th>
            <th>Services</th>
            <th>Status</th>
        </tr>
"""
        for host in scan_data.get('hosts', []):
            ports_str = ', '.join(str(p) for p in host.get('ports', []))
            services_str = ', '.join(host.get('services', []))
            html += f"""        <tr>
            <td>{host.get('host', 'N/A')}</td>
            <td>{ports_str}</td>
            <td>{services_str}</td>
            <td>Active</td>
        </tr>
"""
        html += """    </table>
</body>
</html>"""
        return html

    def generate_summary(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate scan summary statistics."""
        hosts = scan_data.get('hosts', [])
        total_hosts = len(hosts)
        total_open_ports = sum(len(h.get('ports', [])) for h in hosts)
        services = set()
        for host in hosts:
            services.update(host.get('services', []))
        
        return {
            'total_hosts_scanned': total_hosts,
            'total_open_ports': total_open_ports,
            'unique_services': list(services),
            'report_timestamp': datetime.now().isoformat(),
        }
