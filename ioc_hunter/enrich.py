"""Orchestrates enrichment of indicators across all configured providers."""

from __future__ import annotations

import os
from typing import List, Optional, Sequence

from .models import IOCReport, IOCType
from .providers import (
    AbuseIPDBProvider,
    BaseProvider,
    OTXProvider,
    VirusTotalProvider,
    demo_providers,
)
from .utils import detect_type

# Maps a friendly --providers name to its class + env var holding the key.
_REGISTRY = {
    "virustotal": (VirusTotalProvider, "VT_API_KEY"),
    "abuseipdb": (AbuseIPDBProvider, "ABUSEIPDB_API_KEY"),
    "otx": (OTXProvider, "OTX_API_KEY"),
}


def build_providers(
    selected: Optional[Sequence[str]] = None,
    demo: bool = False,
) -> List[BaseProvider]:
    """Instantiate providers from environment variables.

    ``selected`` optionally restricts to a subset (by registry key).
    ``demo`` returns offline canned providers instead.
    """
    if demo:
        return demo_providers()

    names = [n.lower() for n in selected] if selected else list(_REGISTRY)
    providers: List[BaseProvider] = []
    for name in names:
        entry = _REGISTRY.get(name)
        if not entry:
            continue
        cls, env_var = entry
        providers.append(cls(api_key=os.getenv(env_var)))
    return providers


class Enricher:
    """Runs a set of providers over indicators and returns reports."""

    def __init__(self, providers: List[BaseProvider]):
        self.providers = providers

    @property
    def active_providers(self) -> List[str]:
        return [p.name for p in self.providers if p.enabled]

    def enrich(self, ioc: str) -> IOCReport:
        ioc_type = detect_type(ioc)
        report = IOCReport(ioc=ioc, ioc_type=ioc_type)

        if ioc_type is IOCType.UNKNOWN:
            return report  # nothing we can query

        for provider in self.providers:
            if provider.supports(ioc_type):
                report.results.append(provider.query(ioc, ioc_type))
        return report

    def enrich_many(self, iocs: Sequence[str]) -> List[IOCReport]:
        return [self.enrich(ioc) for ioc in iocs]
