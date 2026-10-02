"""Tests for advanced scanner module."""

import pytest
import asyncio
from network_server_discovery.advanced_scanner import AdvancedScanner, ScanResult


class TestAdvancedScanner:
    """Test suite for AdvancedScanner."""

    @pytest.fixture
    def scanner(self):
        return AdvancedScanner(timeout=5, max_workers=50)

    def test_scanner_initialization(self, scanner):
        """Test scanner initialization."""
        assert scanner.timeout == 5
        assert scanner.max_workers == 50
        assert len(scanner.common_ports) > 0

    def test_common_ports(self, scanner):
        """Test common ports dictionary."""
        assert 22 in scanner.common_ports
        assert scanner.common_ports[22] == 'ssh'
        assert 443 in scanner.common_ports
        assert scanner.common_ports[443] == 'https'

    @pytest.mark.asyncio
    async def test_scan_result_creation(self):
        """Test ScanResult dataclass."""
        result = ScanResult(host='127.0.0.1', port=80, is_open=True, service='http')
        assert result.host == '127.0.0.1'
        assert result.port == 80
        assert result.is_open is True
        assert result.service == 'http'
        assert result.timestamp is not None

    def test_scan_result_closed_port(self):
        """Test closed port result."""
        result = ScanResult(host='127.0.0.1', port=65432, is_open=False)
        assert result.is_open is False
        assert result.service is None
