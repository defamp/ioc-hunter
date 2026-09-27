"""Offline demo provider — canned responses, no network or API keys.

Lets anyone run `ioc-hunter --demo ...` and see a full, colourful report
without signing up for API keys. Used for screenshots and CI smoke tests.
"""

from __future__ import annotations

import hashlib

from ..models import IOCType, ProviderResult, Verdict
from .base import BaseProvider

# Hand-crafted results for the indicators used in the README / screenshots.
_FIXTURES = {
    "8.8.8.8": {
        "VirusTotal": (Verdict.CLEAN, "0/94 engines flagged malicious"),
        "AbuseIPDB": (Verdict.CLEAN, "0% abuse confidence, 12 reports"),
        "AlienVault OTX": (Verdict.CLEAN, "0 threat pulse(s)"),
    },
    "185.220.101.1": {
        "VirusTotal": (Verdict.MALICIOUS, "14/94 engines flagged malicious"),
        "AbuseIPDB": (Verdict.MALICIOUS, "100% abuse confidence, 3120 reports"),
        "AlienVault OTX": (Verdict.MALICIOUS, "8 threat pulse(s) — Tor exit node; scanning"),
    },
    "malware-c2.example": {
        "VirusTotal": (Verdict.MALICIOUS, "8/94 engines flagged malicious"),
        "AlienVault OTX": (Verdict.MALICIOUS, "3 threat pulse(s) — malware C2 infrastructure"),
    },
    "44d88612fea8a8f36de82e1278abb02f": {  # EICAR test file md5
        "VirusTotal": (Verdict.MALICIOUS, "63/72 engines flagged malicious"),
        "AlienVault OTX": (Verdict.MALICIOUS, "5 threat pulse(s) — EICAR test signature"),
    },
}


class DemoProvider(BaseProvider):
    """Wraps a real provider's identity but serves canned data."""

    requires_key = False

    def __init__(self, name: str, categories: tuple):
        super().__init__(api_key=None)
        self.name = name
        self.categories = categories

    def _query(self, ioc: str, ioc_type: IOCType) -> ProviderResult:
        fixture = _FIXTURES.get(ioc.lower())
        if fixture and self.name in fixture:
            verdict, summary = fixture[self.name]
        elif fixture:
            verdict, summary = Verdict.UNKNOWN, "no data (demo)"
        else:
            # Deterministic pseudo-result so unknown demo IOCs still look real.
            seed = int(hashlib.sha256((ioc + self.name).encode()).hexdigest(), 16) % 100
            if seed < 15:
                verdict, summary = Verdict.MALICIOUS, f"{seed % 20 + 3}/94 engines flagged malicious"
            elif seed < 35:
                verdict, summary = Verdict.SUSPICIOUS, f"{seed % 3 + 1} threat pulse(s)"
            else:
                verdict, summary = Verdict.CLEAN, "no malicious detections"

        return ProviderResult(
            provider=self.name,
            ioc=ioc,
            success=True,
            verdict=verdict,
            summary=summary,
            details={"demo": True},
        )


def demo_providers():
    """Return the standard trio as offline demo providers."""
    return [
        DemoProvider("VirusTotal", ("ip", "domain", "url", "hash")),
        DemoProvider("AbuseIPDB", ("ip",)),
        DemoProvider("AlienVault OTX", ("ip", "domain", "url", "hash")),
    ]
