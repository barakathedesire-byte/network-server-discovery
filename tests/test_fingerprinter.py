"""Tests for service fingerprinter module."""

import pytest
from network_server_discovery.fingerprinter import ServiceFingerprinter, ServiceFingerprint


class TestServiceFingerprinter:
    """Test suite for ServiceFingerprinter."""

    @pytest.fixture
    def fingerprinter(self):
        return ServiceFingerprinter()

    def test_fingerprinter_initialization(self, fingerprinter):
        """Test fingerprinter initialization."""
        assert len(fingerprinter.service_signatures) > 0
        assert 'ssh' in fingerprinter.service_signatures
        assert 'http' in fingerprinter.service_signatures

    def test_service_signature_structure(self, fingerprinter):
        """Test service signature structure."""
        ssh_sig = fingerprinter.service_signatures['ssh']
        assert 'banner_pattern' in ssh_sig
        assert 'ports' in ssh_sig
        assert 'protocol' in ssh_sig

    def test_service_fingerprint_creation(self):
        """Test ServiceFingerprint dataclass."""
        fp = ServiceFingerprint(
            service='ssh',
            version='2.0',
            banner='SSH-2.0-OpenSSH_7.4',
            signatures=['OpenSSH'],
            confidence=0.95
        )
        assert fp.service == 'ssh'
        assert fp.version == '2.0'
        assert len(fp.signatures) > 0
        assert fp.confidence == 0.95

    def test_extract_version(self, fingerprinter):
        """Test version extraction."""
        banner = 'Apache/2.4.41 (Ubuntu)'
        version = fingerprinter._extract_version(banner)
        assert version is not None
        assert '2.4.41' in version or '2.4' in version
