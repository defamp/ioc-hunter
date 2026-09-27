"""Helpers for normalising and classifying indicators."""

from __future__ import annotations

import re
from typing import List

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


def parse_iocs(raw_items: List[str]) -> List[str]:
    """Clean, refang and de-duplicate a list of raw indicator strings.

    Blank lines and ``#`` comments are ignored so IOC files can be annotated.
    """
    seen = set()
    result: List[str] = []
    for raw in raw_items:
        # Drop inline / full-line comments so IOC files can be annotated.
        line = raw.split("#", 1)[0]
        for token in re.split(r"[\s,;]+", line.strip()):
            if not token:
                continue
            ioc = refang(token)
            key = ioc.lower()
            if key not in seen:
                seen.add(key)
                result.append(ioc)
    return result
