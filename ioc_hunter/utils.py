"""Helpers for normalising and classifying indicators."""

from __future__ import annotations

import ipaddress
import re
from typing import List, Optional
from urllib.parse import urlparse

from .models import IOCType, is_ip

# Defanging patterns commonly seen in threat reports / SOC tickets.
_DEFANG_REPLACEMENTS = (
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[dot]", "."),
    ("(dot)", "."),
    (" dot ", "."),
    ("[:]", ":"),
    ("[://]", "://"),
    ("hxxps", "https"),
    ("hxxp", "http"),
    ("fxp", "ftp"),
)

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](-?[a-zA-Z0-9])*\.)+[a-zA-Z]{2,}$"
)
_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")

# A "#" starts a comment only at the start of a line or after whitespace, so
# URL fragments such as https://evil.com/login#token survive.
_COMMENT_RE = re.compile(r"(?:^|\s)#")

# Names that only resolve inside an organisation. Sending them to a public
# threat-intel service leaks internal infrastructure. (Reserved-for-docs TLDs
# like .example/.test are not internal and are still queried.)
_INTERNAL_SUFFIXES = (
    ".local", ".localhost", ".localdomain", ".internal", ".intranet",
    ".corp", ".lan", ".home", ".home.arpa", ".private",
)


def refang(value: str) -> str:
    """Turn a defanged indicator back into a real one.

    e.g. ``hxxps://evil[.]com`` -> ``https://evil.com``
    """
    out = value.strip().strip("\"'")
    lowered = out
    for needle, repl in _DEFANG_REPLACEMENTS:
        lowered = lowered.replace(needle, repl)
    return lowered


def detect_type(value: str) -> IOCType:
    """Classify a single (already refanged) indicator."""
    v = value.strip()
    if not v:
        return IOCType.UNKNOWN

    # Hashes first — they are unambiguous by length + hex charset.
    if _HEX_RE.match(v):
        length = len(v)
        if length == 32:
            return IOCType.MD5
        if length == 40:
            return IOCType.SHA1
        if length == 64:
            return IOCType.SHA256

    ip_type = is_ip(v)
    if ip_type:
        return ip_type

    if v.lower().startswith(("http://", "https://", "ftp://")):
        return IOCType.URL

    if _DOMAIN_RE.match(v):
        return IOCType.DOMAIN

    return IOCType.UNKNOWN


def internal_reason(ioc: str, ioc_type: IOCType) -> Optional[str]:
    """Why ``ioc`` looks internal (and must not leave the network), or None.

    Covers non-global IPs (RFC 1918, loopback, link-local, CGNAT, …) and
    internal-only domain suffixes, for bare values and for URL hosts. Hashes
    can't be classified and are never flagged.
    """
    host = ioc
    if ioc_type is IOCType.URL:
        host = urlparse(ioc).hostname or ""
    elif ioc_type not in (IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN):
        return None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        name = host.lower().rstrip(".")
        if name.endswith(_INTERNAL_SUFFIXES) or name in ("localhost",):
            return "internal hostname"
        return None
    if not ip.is_global:
        return "private/non-routable IP"
    return None


def parse_iocs(raw_items: List[str]) -> List[str]:
    """Clean, refang and de-duplicate a list of raw indicator strings.

    Blank lines and ``#`` comments are ignored so IOC files can be annotated.
    """
    seen = set()
    result: List[str] = []
    for raw in raw_items:
        # Drop inline / full-line comments so IOC files can be annotated.
        line = _COMMENT_RE.split(raw, 1)[0]
        for token in re.split(r"[\s,;]+", line.strip()):
            if not token:
                continue
            ioc = refang(token)
            key = ioc.lower()
            if key not in seen:
                seen.add(key)
                result.append(ioc)
    return result
