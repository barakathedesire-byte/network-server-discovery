import os
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file
from flask_cors import CORS

from .advanced_scanner import AdvancedNetworkScanner
from .reporting import ReportGenerator, ScanHistory


def create_app() -> Flask:
    root_dir = Path(__file__).resolve().parent.parent
    template_dir = root_dir / "templates"
    static_dir = root_dir / "static"

    app = Flask(
        __name__,
        template_folder=str(template_dir),
        static_folder=str(static_dir),
    )
    app.config["SECRET_KEY"] = os.environ.get("NSD_SECRET_KEY", "change-me-in-production")
    app.config["JSON_SORT_KEYS"] = False
    CORS(app)

    scan_results = {}
    scan_counter = 0
    scan_history = ScanHistory()

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/scan", methods=["POST"])
    def start_scan():
        nonlocal scan_counter
        data = request.get_json(silent=True) or {}
        target = data.get("target", "").strip()
        if not target:
            return jsonify({"error": "Target is required"}), 400

        if len(target) > 255:
            return jsonify({"error": "Target is too long"}), 400

        if not _is_allowed_target(target):
            return jsonify({"error": "Invalid target format"}), 400

        ports_raw = data.get("ports", "")
        ports = None
        if ports_raw:
            try:
                ports = [int(p.strip()) for p in ports_raw.split(",") if p.strip()]
            except ValueError:
                return jsonify({"error": "Ports must be comma-separated integers"}), 400
            if len(ports) > 1024:
                return jsonify({"error": "Too many ports requested"}), 400

        scan_counter += 1
        scan_id = f"scan_{scan_counter}"

        try:
            scanner = AdvancedNetworkScanner(
                target=target,
                ports=ports,
                timeout=float(data.get("timeout", 1.5)),
                threads=min(max(int(data.get("threads", 20)), 1), 128),
                vhost_scan=bool(data.get("vhost_scan", False)),
                dns_enum=bool(data.get("dns_enum", False)),
            )
            result = scanner.scan()
            scan_data = result.to_dict()
            scan_results[scan_id] = result
            scan_history.save_scan(scan_id, scan_data)
            return jsonify({"scan_id": scan_id, "summary": result.summary(), "data": scan_data}), 200
        except Exception as exc:  # pragma: no cover - defensive route guard
            return jsonify({"error": str(exc)}), 400

    @app.route("/api/scan/<scan_id>", methods=["GET"])
    def get_scan(scan_id: str):
        result = scan_results.get(scan_id)
        if result is not None:
            return jsonify({"scan_id": scan_id, "summary": result.summary(), "data": result.to_dict()}), 200

        scan_data = scan_history.get_scan(scan_id)
        if scan_data:
            return jsonify({"scan_id": scan_id, "data": scan_data}), 200
        return jsonify({"error": "Scan not found"}), 404

    @app.route("/api/history", methods=["GET"])
    def get_history():
        return jsonify({"scans": scan_history.get_history()}), 200

    @app.route("/api/scan/<scan_id>/delete", methods=["DELETE"])
    def delete_scan(scan_id: str):
        scan_results.pop(scan_id, None)
        if scan_history.delete_scan(scan_id):
            return jsonify({"success": True}), 200
        return jsonify({"error": "Scan not found"}), 404

    @app.route("/api/scan/<scan_id>/export", methods=["GET"])
    def export_scan(scan_id: str):
        result = scan_results.get(scan_id)
        if result is not None:
            scan_data = result.to_dict()
        else:
            scan_data = scan_history.get_scan(scan_id)
            if not scan_data:
                return jsonify({"error": "Scan not found"}), 404

        fmt = request.args.get("format", "json").lower()
        if fmt == "html":
            payload = ReportGenerator.generate_html(scan_data)
            mime = "text/html"
            filename = f"scan_{scan_id}.html"
        elif fmt == "csv":
            payload = ReportGenerator.generate_csv(scan_data)
            mime = "text/csv"
            filename = f"scan_{scan_id}.csv"
        else:
            payload = ReportGenerator.generate_json(scan_data)
            mime = "application/json"
            filename = f"scan_{scan_id}.json"

        return send_file(
            __make_bytes_io(payload),
            mimetype=mime,
            as_attachment=True,
            download_name=filename,
        )

    @app.route("/api/offline-server", methods=["POST"])
    def add_offline_server():
        data = request.get_json(silent=True) or {}
        scan_id = data.get("scan_id")
        if scan_id not in scan_results:
            return jsonify({"error": "Invalid scan_id"}), 400

        ip = str(data.get("ip", "")).strip()
        hostname = str(data.get("hostname", "")).strip()
        services = data.get("services", [])
        if not ip or not hostname:
            return jsonify({"error": "IP and hostname are required"}), 400

        if not _is_allowed_ip(ip):
            return jsonify({"error": "Invalid IP format"}), 400

        result = scan_results[scan_id]
        result.offline_servers.append(
            {
                "ip": ip,
                "hostname": hostname,
                "services": list(services)[:50],
                "status": "offline",
            }
        )
        return jsonify({"success": True}), 200

    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok"}), 200

    return app


def _make_bytes_io(payload: str):
    buffer = __import__("io").BytesIO(payload.encode("utf-8"))
    buffer.seek(0)
    return buffer


def _is_allowed_target(value: str) -> bool:
    value = value.strip()
    if not value or len(value) > 255:
        return False
    if any(ch.isspace() for ch in value):
        return False
    if any(ord(ch) < 32 for ch in value):
        return False
    if "/" in value:
        try:
            import ipaddress
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            return False
    if value.count(":") > 1:
        return False
    if "." in value or "-" in value:
        # allow domain-like names and IPs but reject malformed controls
        return True
    return True


def _is_allowed_ip(value: str) -> bool:
    try:
        import ipaddress
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


app = create_app()
