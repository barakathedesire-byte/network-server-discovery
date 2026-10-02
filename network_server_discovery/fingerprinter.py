"""Service fingerprinting and version detection."""

import socket
import ssl
import re
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class ServiceFingerprint:
    """Service fingerprint information."""
    service: str
    version: Optional[str]
    banner: str
    signatures: list
    confidence: float


class ServiceFingerprinter:
    """Identify and fingerprint network services."""

    def __init__(self):
        self.service_signatures = {
            'ssh': {
                'banner_pattern': r'SSH-([\d.]+)',
                'ports': [22],
                'protocol': 'ssh'
            },
            'http': {
                'banner_pattern': r'Server: ([^\r\n]+)',
                'ports': [80, 8080, 8000],
                'protocol': 'http'
            },
            'https': {
                'banner_pattern': r'Server: ([^\r\n]+)',
                'ports': [443, 8443],
                'protocol': 'https'
            },
            'smtp': {
                'banner_pattern': r'(\d{3} .+)',
                'ports': [25, 587],
                'protocol': 'smtp'
            },
            'ftp': {
                'banner_pattern': r'(\d{3} .+)',
                'ports': [21],
                'protocol': 'ftp'
            },
            'mysql': {
                'banner_pattern': r'MySQL (\d+\.\d+\.\d+)',
                'ports': [3306],
                'protocol': 'mysql'
            },
            'postgresql': {
                'banner_pattern': r'PostgreSQL (\d+\.\d+)',
                'ports': [5432],
                'protocol': 'postgresql'
            },
        }

    def fingerprint_service(self, host: str, port: int, banner: str) -> ServiceFingerprint:
        """Fingerprint a service based on banner."""
        detected_service = self._detect_service(port, banner)
        version = self._extract_version(banner)
        signatures = self._match_signatures(banner)
        confidence = self._calculate_confidence(detected_service, banner)

        return ServiceFingerprint(
            service=detected_service,
            version=version,
            banner=banner,
            signatures=signatures,
            confidence=confidence
        )

    def _detect_service(self, port: int, banner: str) -> str:
        """Detect service from port and banner."""
        for service, info in self.service_signatures.items():
            if port in info['ports']:
                if re.search(info['banner_pattern'], banner, re.IGNORECASE):
                    return service
        return 'unknown'

    def _extract_version(self, banner: str) -> Optional[str]:
        """Extract version from banner."""
        patterns = [
            r'(\d+\.\d+\.\d+)',
            r'(\d+\.\d+)',
            r'v(\d+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, banner)
            if match:
                return match.group(1)
        return None

    def _match_signatures(self, banner: str) -> list:
        """Match known signatures in banner."""
        signatures = []
        signature_map = {
            'Apache': r'Apache',
            'Nginx': r'nginx',
            'IIS': r'IIS',
            'OpenSSH': r'OpenSSH',
            'OpenSSL': r'OpenSSL',
        }
        for sig, pattern in signature_map.items():
            if re.search(pattern, banner, re.IGNORECASE):
                signatures.append(sig)
        return signatures

    def _calculate_confidence(self, service: str, banner: str) -> float:
        """Calculate confidence of detection."""
        if service == 'unknown':
            return 0.0
        if len(banner) > 50:
            return 0.95
        if len(banner) > 20:
            return 0.75
        return 0.5

    def get_ssl_certificate_info(self, host: str, port: int) -> Optional[Dict]:
        """Get SSL certificate information."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                    }
        except Exception as e:
            logger.debug(f"Error getting SSL cert for {host}:{port}: {e}")
            return None
