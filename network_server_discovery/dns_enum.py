"""DNS enumeration and discovery utilities."""

import dns.resolver
import dns.rdatatype
import dns.zone
import dns.query
from typing import Dict, List, Set, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class DNSRecord:
    """DNS record information."""
    domain: str
    record_type: str
    value: str
    ttl: int


class DNSEnumerator:
    """Enumerate DNS records and discover services."""

    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whois', 'autodiscover', 'autoconfig', 'api', 'admin',
            'dev', 'test', 'staging', 'prod', 'app', 'blog', 'shop', 'store',
        ]
        self.record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SRV']

    def enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate common subdomains."""
        discovered = []
        for subdomain in self.common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                self.resolver.resolve(full_domain, 'A')
                discovered.append(full_domain)
                logger.info(f"Found subdomain: {full_domain}")
            except Exception:
                pass
        return discovered

    def get_dns_records(self, domain: str, record_type: str = 'A') -> List[DNSRecord]:
        """Get DNS records for a domain."""
        records = []
        try:
            answers = self.resolver.resolve(domain, record_type)
            for rdata in answers:
                records.append(DNSRecord(
                    domain=domain,
                    record_type=record_type,
                    value=str(rdata),
                    ttl=answers.rrset.ttl
                ))
        except Exception as e:
            logger.debug(f"Error resolving {domain} for {record_type}: {e}")
        return records

    def get_all_records(self, domain: str) -> Dict[str, List[DNSRecord]]:
        """Get all DNS records for a domain."""
        all_records = {}
        for record_type in self.record_types:
            all_records[record_type] = self.get_dns_records(domain, record_type)
        return all_records

    def get_mx_records(self, domain: str) -> List[Dict]:
        """Get MX records for a domain."""
        mx_records = []
        try:
            answers = self.resolver.resolve(domain, 'MX')
            for rdata in sorted(answers, key=lambda x: x.preference):
                mx_records.append({
                    'preference': rdata.preference,
                    'exchange': str(rdata.exchange),
                    'ttl': answers.rrset.ttl
                })
        except Exception as e:
            logger.debug(f"Error getting MX records for {domain}: {e}")
        return mx_records

    def check_zone_transfer(self, domain: str, nameserver: Optional[str] = None) -> Optional[List[str]]:
        """Attempt AXFR zone transfer."""
        try:
            if nameserver is None:
                ns_records = self.get_dns_records(domain, 'NS')
                if not ns_records:
                    return None
                nameserver = ns_records[0].value.rstrip('.')
            
            zone = dns.zone.from_xfr(dns.query.xfr(nameserver, domain))
            return [str(node) for node in zone.iterate_rdatasets()]
        except Exception as e:
            logger.debug(f"Zone transfer failed for {domain}: {e}")
            return None
