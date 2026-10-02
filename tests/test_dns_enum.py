"""Tests for DNS enumeration module."""

import pytest
from network_server_discovery.dns_enum import DNSEnumerator, DNSRecord


class TestDNSEnumerator:
    """Test suite for DNSEnumerator."""

    @pytest.fixture
    def enumerator(self):
        return DNSEnumerator()

    def test_enumerator_initialization(self, enumerator):
        """Test enumerator initialization."""
        assert enumerator.resolver is not None
        assert len(enumerator.common_subdomains) > 0
        assert len(enumerator.record_types) > 0

    def test_common_subdomains(self, enumerator):
        """Test common subdomains list."""
        assert 'www' in enumerator.common_subdomains
        assert 'mail' in enumerator.common_subdomains
        assert 'admin' in enumerator.common_subdomains

    def test_record_types(self, enumerator):
        """Test record types list."""
        assert 'A' in enumerator.record_types
        assert 'AAAA' in enumerator.record_types
        assert 'MX' in enumerator.record_types
        assert 'NS' in enumerator.record_types

    def test_dns_record_creation(self):
        """Test DNSRecord dataclass."""
        record = DNSRecord(
            domain='example.com',
            record_type='A',
            value='192.0.2.1',
            ttl=3600
        )
        assert record.domain == 'example.com'
        assert record.record_type == 'A'
        assert record.value == '192.0.2.1'
        assert record.ttl == 3600
