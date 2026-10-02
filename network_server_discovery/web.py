from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from datetime import datetime
import io
import json

from .advanced_scanner import AdvancedNetworkScanner

app = Flask(__name__)
CORS(app)

scan_results = {}
scan_counter = 0


@app.route("/")
def index():
    return app.send_static_file("index.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    global scan_counter
    data = request.get_json(silent=True) or {}
    target = data.get("target")
    if not target:
        return jsonify({"error": "Target is required"}), 400

    ports_raw = data.get("ports", "")
    ports = None
    if ports_raw:
        try:
            ports = [int(p.strip()) for p in ports_raw.split(",") if p.strip()]
        except ValueError:
            return jsonify({"error": "Ports must be comma-separated integers"}), 400

    scan_counter += 1
    scan_id = f"scan_{scan_counter}"

    try:
        scanner = AdvancedNetworkScanner(
            target=target,
            ports=ports,
            timeout=float(data.get("timeout", 1.5)),
            threads=int(data.get("threads", 20)),
            vhost_scan=bool(data.get("vhost_scan", False)),
            dns_enum=bool(data.get("dns_enum", False)),
        )
        result = scanner.scan()
        scan_results[scan_id] = result
        return jsonify({"scan_id": scan_id, "summary": result.summary(), "data": result.to_dict()}), 200
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/scan/<scan_id>", methods=["GET"])
def get_scan(scan_id: str):
    result = scan_results.get(scan_id)
    if not result:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({"scan_id": scan_id, "summary": result.summary(), "data": result.to_dict()}), 200


@app.route("/api/scan/<scan_id>/export", methods=["GET"])
def export_scan(scan_id: str):
    result = scan_results.get(scan_id)
    if not result:
        return jsonify({"error": "Scan not found"}), 404

    payload = json.dumps(result.to_dict(), indent=2).encode("utf-8")
    buffer = io.BytesIO(payload)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name=f"scan_{scan_id}.json", mimetype="application/json")


@app.route("/api/offline-server", methods=["POST"])
def add_offline_server():
    data = request.get_json(silent=True) or {}
    scan_id = data.get("scan_id")
    result = scan_results.get(scan_id)
    if not result:
        return jsonify({"error": "Invalid scan_id"}), 400

    ip = data.get("ip")
    hostname = data.get("hostname")
    services = data.get("services", [])
    if not ip or not hostname:
        return jsonify({"error": "IP and hostname are required"}), 400

    result.offline_servers.append({
        "ip": ip,
        "hostname": hostname,
        "services": services,
        "status": "offline",
        "added_at": datetime.utcnow().isoformat() + "Z",
    })
    return jsonify({"success": True}), 200


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200
