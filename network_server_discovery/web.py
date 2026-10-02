"""Web interface for network server discovery."""

from flask import Flask, render_template, request, jsonify
from typing import Dict, List
import logging

logger = logging.getLogger(__name__)


class WebInterface:
    """Web interface for scanning and visualization."""

    def __init__(self, host: str = '0.0.0.0', port: int = 5000):
        self.app = Flask(__name__)
        self.host = host
        self.port = port
        self.scan_results = {}
        self._setup_routes()

    def _setup_routes(self):
        """Setup Flask routes."""
        @self.app.route('/')
        def index():
            return self.render_dashboard()

        @self.app.route('/api/scan', methods=['POST'])
        def start_scan():
            data = request.json
            target = data.get('target')
            scan_type = data.get('type', 'basic')
            return jsonify({'status': 'started', 'target': target})

        @self.app.route('/api/results')
        def get_results():
            return jsonify(self.scan_results)

        @self.app.route('/api/results/<target>')
        def get_target_results(target):
            return jsonify(self.scan_results.get(target, {}))

        @self.app.route('/api/history')
        def get_history():
            return jsonify({'scans': list(self.scan_results.keys())})

    def render_dashboard(self) -> str:
        """Render dashboard HTML."""
        return """<!DOCTYPE html>
<html>
<head>
    <title>Network Server Discovery Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        .card { background: white; padding: 20px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input, select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #3498db; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; }
        button:hover { background: #2980b9; }
        .results { margin-top: 20px; }
        .result-item { background: #ecf0f1; padding: 10px; margin: 5px 0; border-radius: 4px; }
        .status-active { color: #27ae60; font-weight: bold; }
        .status-inactive { color: #e74c3c; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #34495e; color: white; }
        tr:hover { background-color: #f5f5f5; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Network Server Discovery Dashboard</h1>
            <p>Scan and monitor network servers</p>
        </div>

        <div class="card">
            <h2>Start Scan</h2>
            <form id="scanForm">
                <div class="form-group">
                    <label for="target">Target (IP/Domain/Network):</label>
                    <input type="text" id="target" name="target" placeholder="e.g., 192.168.1.0/24 or example.com" required>
                </div>
                <div class="form-group">
                    <label for="scanType">Scan Type:</label>
                    <select id="scanType" name="scanType">
                        <option value="quick">Quick Scan</option>
                        <option value="standard">Standard Scan</option>
                        <option value="intensive">Intensive Scan</option>
                        <option value="custom">Custom Scan</option>
                    </select>
                </div>
                <button type="submit">Start Scan</button>
            </form>
        </div>

        <div class="card">
            <h2>Results</h2>
            <div id="results" class="results">
                <p>No scans yet. Start a scan to see results.</p>
            </div>
        </div>

        <div class="card">
            <h2>Recent Scans</h2>
            <table>
                <tr>
                    <th>Target</th>
                    <th>Scan Type</th>
                    <th>Status</th>
                    <th>Results</th>
                </tr>
                <tbody id="scanHistory"></tbody>
            </table>
        </div>
    </div>

    <script>
        document.getElementById('scanForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const target = document.getElementById('target').value;
            const scanType = document.getElementById('scanType').value;
            
            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target, type: scanType })
                });
                const data = await response.json();
                alert('Scan started for: ' + target);
                loadResults();
            } catch (error) {
                alert('Error starting scan: ' + error.message);
            }
        });

        async function loadResults() {
            try {
                const response = await fetch('/api/results');
                const data = await response.json();
                updateResultsDisplay(data);
            } catch (error) {
                console.error('Error loading results:', error);
            }
        }

        function updateResultsDisplay(data) {
            const resultsDiv = document.getElementById('results');
            if (Object.keys(data).length === 0) {
                resultsDiv.innerHTML = '<p>No results available.</p>';
                return;
            }
            
            let html = '';
            for (const [target, results] of Object.entries(data)) {
                html += `<div class="result-item"><strong>${target}</strong>: ${JSON.stringify(results).substring(0, 100)}...</div>`;
            }
            resultsDiv.innerHTML = html;
        }

        // Load results on page load and periodically
        loadResults();
        setInterval(loadResults, 5000);
    </script>
</body>
</html>"""

    def run(self, debug: bool = True):
        """Run the web server."""
        logger.info(f"Starting web interface on {self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port, debug=debug)
