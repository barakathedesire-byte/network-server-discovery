"""Tests for reporting module."""

import pytest
import json
from pathlib import Path
from network_server_discovery.reporting import Reporter


class TestReporter:
    """Test suite for Reporter."""

    @pytest.fixture
    def reporter(self, tmp_path):
        return Reporter(output_dir=str(tmp_path))

    def test_reporter_initialization(self, reporter):
        """Test reporter initialization."""
        assert reporter.output_dir.exists()
        assert reporter.timestamp is not None

    def test_generate_json_report(self, reporter):
        """Test JSON report generation."""
        scan_data = {
            'hosts': [
                {'host': '127.0.0.1', 'ports': [80, 443]}
            ]
        }
        filepath = reporter.generate_json_report(scan_data)
        assert Path(filepath).exists()
        
        with open(filepath) as f:
            data = json.load(f)
        assert data == scan_data

    def test_generate_summary(self, reporter):
        """Test summary generation."""
        scan_data = {
            'hosts': [
                {'host': '127.0.0.1', 'ports': [80], 'services': ['http']},
                {'host': '127.0.0.2', 'ports': [443], 'services': ['https']}
            ]
        }
        summary = reporter.generate_summary(scan_data)
        assert summary['total_hosts_scanned'] == 2
        assert summary['total_open_ports'] == 2
        assert len(summary['unique_services']) > 0
