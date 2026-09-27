"""VirusTotal v3 provider."""

from __future__ import annotations

import base64

from ..models import IOCType, ProviderResult, Verdict
from .base import BaseProvider

API_ROOT = "https://www.virustotal.com/api/v3"


class VirusTotalProvider(BaseProvider):
    name = "VirusTotal"
    categories = ("ip", "domain", "url", "hash")
    requires_key = True

    def _endpoint(self, ioc: str, ioc_type: IOCType):
        """Return (api_url, gui_url) for the indicator."""
        cat = ioc_type.category
        if cat == "ip":
            return f"{API_ROOT}/ip_addresses/{ioc}", f"https://www.virustotal.com/gui/ip-address/{ioc}"
        if cat == "domain":
            return f"{API_ROOT}/domains/{ioc}", f"https://www.virustotal.com/gui/domain/{ioc}"
        if cat == "hash":
            return f"{API_ROOT}/files/{ioc}", f"https://www.virustotal.com/gui/file/{ioc}"
        # url — id is the unpadded urlsafe base64 of the URL
        url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
        return f"{API_ROOT}/urls/{url_id}", f"https://www.virustotal.com/gui/url/{url_id}"

    def _query(self, ioc: str, ioc_type: IOCType) -> ProviderResult:
        api_url, gui_url = self._endpoint(ioc, ioc_type)
        resp = self.session.get(
            api_url, headers={"x-apikey": self.api_key}, timeout=self.timeout
        )
        if resp.status_code == 404:
            return ProviderResult(
                provider=self.name, ioc=ioc, success=True,
                verdict=Verdict.UNKNOWN, summary="not found in VirusTotal", link=gui_url,
            )
        if resp.status_code == 401:
            return self._error(ioc, "invalid API key (401)")
        if resp.status_code == 429:
            return self._error(ioc, "rate limit exceeded (429)")
        resp.raise_for_status()

        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        harmless = int(stats.get("harmless", 0))
        undetected = int(stats.get("undetected", 0))
        total = malicious + suspicious + harmless + undetected

        if malicious >= 3:
            verdict = Verdict.MALICIOUS
        elif malicious >= 1 or suspicious >= 1:
            verdict = Verdict.SUSPICIOUS
        elif total > 0:
            verdict = Verdict.CLEAN
        else:
            verdict = Verdict.UNKNOWN

        return ProviderResult(
            provider=self.name,
            ioc=ioc,
            success=True,
            verdict=verdict,
            summary=f"{malicious}/{total} engines flagged malicious",
            details={
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "reputation": attrs.get("reputation"),
            },
            link=gui_url,
        )
