import os
from pathlib import Path

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

from .advanced_scanner import AdvancedNetworkScanner
from .reporting import ReportGenerator, ScanHistory


class ScanApp:
    def __init__(self):
        self.root_dir = Path(__file__).resolve().parent.parent
        self.template_dir = self.root_dir / "templates"
        self.static_dir = self.root_dir / "static"
        self.app = Flask(
            __name__,
            template_folder=str(self.template_dir),
            static_folder=str(self.static_dir),
        )
        self.app.config["SECRET_KEY"] = os.environ.get("NSD_SECRET_KEY", "change-me-in-production")
        self.app.config["JSON_SORT_KEYS"] = False
        CORS(self.app)
        self.scan_results = {}
        self.scan_counter = 0
        self.scan_history = ScanHistory()
        self._register_routes()

    def _register_routes(self):
        app = self.app

        @app.route("/")
        def index():
            return app.send_static_file("index.html") if (self.static_dir / "index.html").exists() else __import__("flask").render_template("index.html")

        @app.route("/api/scan", methods=["POST"])
        def start_scan():
            data = request.get_json(silent=True) or {}
            target = str(data.get("target", "")).strip()
            if not target:
                return jsonify({"error": "Target is required"}), 400
            try:
                ports = None
                raw_ports = data.get("ports", "")
                if raw_ports:
                    ports = [int(p.strip()) for p in raw_ports.split(",") if p.strip()]
                scanner = AdvancedNetworkScanner(
                    target=target,
                    ports=ports,
                    timeout=float(data.get("timeout", 1.5)),
                    threads=max(1, min(128, int(data.get("threads", 20)))),
                    vhost_scan=bool(data.get("vhost_scan", False)),
                    dns_enum=bool(data.get("dns_enum", False)),
                )
                result = scanner.scan()
                self.scan_counter += 1
                scan_id = f"scan_{self.scan_counter}"
                self.scan_results[scan_id] = result
                self.scan_history.save_scan(scan_id, result.to_dict())
                return jsonify({"scan_id": scan_id, "summary": result.summary(), "data": result.to_dict()}), 200
            except Exception as exc:
                return jsonify({"error": str(exc)}), 400

        @app.route("/api/history", methods=["GET"])
        def get_history():
            return jsonify({"scans": self.scan_history.get_history()}), 200

        @app.route("/api/scan/<scan_id>", methods=["GET"])
        def get_scan(scan_id: str):
            result = self.scan_results.get(scan_id)
            if result is not None:
                return jsonify({"scan_id": scan_id, "summary": result.summary(), "data": result.to_dict()}), 200
            data = self.scan_history.get_scan(scan_id)
            if data:
                return jsonify({"scan_id": scan_id, "data": data}), 200
            return jsonify({"error": "Scan not found"}), 404

        @app.route("/api/scan/<scan_id>/export", methods=["GET"])
        def export_scan(scan_id: str):
            data = self.scan_results.get(scan_id)
            if data is None:
                data = self.scan_history.get_scan(scan_id)
                if data is None:
                    return jsonify({"error": "Scan not found"}), 404
            fmt = request.args.get("format", "json").lower()
            if fmt == "html":
                payload = ReportGenerator.generate_html(data)
                mimetype = "text/html"
                filename = f"scan_{scan_id}.html"
            elif fmt == "csv":
                payload = ReportGenerator.generate_csv(data)
                mimetype = "text/csv"
                filename = f"scan_{scan_id}.csv"
            else:
                payload = ReportGenerator.generate_json(data)
                mimetype = "application/json"
                filename = f"scan_{scan_id}.json"
            return send_file(__io_buffer(payload), mimetype=mimetype, as_attachment=True, download_name=filename)

        @app.route("/api/scan/<scan_id>/delete", methods=["DELETE"])
        def delete_scan(scan_id: str):
            self.scan_results.pop(scan_id, None)
            if self.scan_history.delete_scan(scan_id):
                return jsonify({"success": True}), 200
            return jsonify({"error": "Scan not found"}), 404

        @app.route("/api/offline-server", methods=["POST"])
        def add_offline_server():
            payload = request.get_json(silent=True) or {}
            scan_id = payload.get("scan_id")
            result = self.scan_results.get(scan_id)
            if not result:
                return jsonify({"error": "Invalid scan_id"}), 400
            ip = str(payload.get("ip", "")).strip()
            hostname = str(payload.get("hostname", "")).strip()
            services = payload.get("services", [])
            if not ip or not hostname:
                return jsonify({"error": "IP and hostname are required"}), 400
            result.offline_servers.append({
                "ip": ip,
                "hostname": hostname,
                "services": list(services)[:50],
                "status": "offline",
            })
            return jsonify({"success": True}), 200

        @app.route("/api/health", methods=["GET"])
        def health():
            return jsonify({"status": "ok"}), 200


def __io_buffer(payload: str):
    import io
    buffer = io.BytesIO(payload.encode("utf-8"))
    buffer.seek(0)
    return buffer


app = ScanApp().app


def run_web_server():
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)


if __name__ == "__main__":
    run_web_server()
