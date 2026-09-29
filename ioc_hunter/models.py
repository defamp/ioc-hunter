"""Data models shared across IOC Hunter."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class IOCType(str, Enum):
    """The kind of indicator being enriched."""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    UNKNOWN = "unknown"

    @property
    def category(self) -> str:
        """Coarse category used by providers to decide support."""
        if self in (IOCType.IPV4, IOCType.IPV6):
            return "ip"
        if self in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            return "hash"
        return self.value  # "domain", "url" or "unknown"


class Verdict(str, Enum):
    """Normalised verdict severity, comparable via `level`."""

    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"
    ERROR = "error"

    @property
    def level(self) -> int:
        return {
            Verdict.ERROR: -1,
            Verdict.UNKNOWN: 0,
            Verdict.CLEAN: 1,
            Verdict.SUSPICIOUS: 2,
            Verdict.MALICIOUS: 3,
        }[self]


@dataclass
class ProviderResult:
    """The outcome of querying a single provider for one indicator."""

    provider: str
    ioc: str
    success: bool = False
    verdict: Verdict = Verdict.UNKNOWN
    summary: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    link: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "success": self.success,
            "verdict": self.verdict.value,
            "summary": self.summary,
            "details": self.details,
            "link": self.link,
            "error": self.error,
        }


@dataclass
class IOCReport:
    """Aggregated enrichment result for one indicator."""

    ioc: str
    ioc_type: IOCType
    results: List[ProviderResult] = field(default_factory=list)
    note: Optional[str] = None  # e.g. why the indicator was not queried

    @property
    def verdict(self) -> Verdict:
        """Worst (highest severity) verdict across successful providers."""
        successful = [r.verdict for r in self.results if r.success]
        if not successful:
            return Verdict.UNKNOWN
        return max(successful, key=lambda v: v.level)

    @property
    def malicious_sources(self) -> int:
        return sum(1 for r in self.results if r.success and r.verdict == Verdict.MALICIOUS)

    @property
    def checked_sources(self) -> int:
        return sum(1 for r in self.results if r.success)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ioc": self.ioc,
            "type": self.ioc_type.value,
            "verdict": self.verdict.value,
            "malicious_sources": self.malicious_sources,
            "checked_sources": self.checked_sources,
            "results": [r.to_dict() for r in self.results],
            "note": self.note,
        }


def is_ip(value: str) -> Optional[IOCType]:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    return IOCType.IPV4 if ip.version == 4 else IOCType.IPV6
