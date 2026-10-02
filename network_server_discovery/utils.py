import json
from pathlib import Path


def write_json_report(path: str, result) -> None:
    Path(path).write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")


def write_html_report(path: str, result) -> None:
    rows = []
    for host in result.hosts:
        services = "<br>".join(
            f"{service.name} ({service.port})" for service in host.services
        )
        rows.append(f"<tr><td>{host.ip}</td><td>{host.hostname or 'unknown'}</td><td>{services or 'n/a'}</td></tr>")

    html = f"""
    <html>
      <head><title>Server Discovery Report</title></head>
      <body>
        <h1>Server Discovery Report</h1>
        <p>Target: {result.target}</p>
        <table border="1" cellpadding="6">
          <thead><tr><th>IP</th><th>Hostname</th><th>Services</th></tr></thead>
          <tbody>{''.join(rows) if rows else '<tr><td colspan="3">No hosts discovered</td></tr>'}</tbody>
        </table>
      </body>
    </html>
    """
    Path(path).write_text(html, encoding="utf-8")
