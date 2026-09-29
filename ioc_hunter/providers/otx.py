"""AlienVault OTX provider."""

from __future__ import annotations

from ..models import IOCType, ProviderResult, Verdict
from .base import BaseProvider

API_ROOT = "https://otx.alienvault.com/api/v1/indicators"

_SECTION = {
    IOCType.IPV4: "IPv4",
    IOCType.IPV6: "IPv6",
    IOCType.DOMAIN: "domain",
    IOCType.URL: "url",
    IOCType.MD5: "file",
    IOCType.SHA1: "file",
    IOCType.SHA256: "file",
}


class OTXProvider(BaseProvider):
    name = "AlienVault OTX"
    categories = ("ip", "domain", "url", "hash")
    requires_key = True

    def _query(self, ioc: str, ioc_type: IOCType) -> ProviderResult:
        section = _SECTION.get(ioc_type)
        if section is None:
            return self._error(ioc, f"unsupported type: {ioc_type.value}")

        url = f"{API_ROOT}/{section}/{ioc}/general"
        resp = self.session.get(
            url, headers={"X-OTX-API-KEY": self.api_key}, timeout=self.timeout
        )
        if resp.status_code == 403:
            return self._error(ioc, "invalid API key (403)")
        if resp.status_code == 429:
            return self._error(ioc, "rate limit exceeded (429)")
        if resp.status_code == 404:
            return ProviderResult(
                provider=self.name, ioc=ioc, success=True,
                verdict=Verdict.UNKNOWN, summary="no OTX data",
            )
        resp.raise_for_status()

        data = resp.json()
        pulse_info = data.get("pulse_info", {}) or {}
        pulses = int(pulse_info.get("count", 0))
        names = [p.get("name", "") for p in pulse_info.get("pulses", [])[:3]]

        if pulses >= 3:
            verdict = Verdict.MALICIOUS
        elif pulses >= 1:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.CLEAN

        summary = f"{pulses} threat pulse(s)"
        if names:
            summary += " — " + "; ".join(n for n in names if n)

        return ProviderResult(
            provider=self.name,
            ioc=ioc,
            success=True,
            verdict=verdict,
            summary=summary,
            details={"pulse_count": pulses, "pulses": names},
            link=f"https://otx.alienvault.com/indicator/{section.lower()}/{ioc}",
        )
