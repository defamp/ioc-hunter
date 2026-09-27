"""AbuseIPDB v2 provider (IP addresses only)."""

from __future__ import annotations

from ..models import IOCType, ProviderResult, Verdict
from .base import BaseProvider

API_URL = "https://api.abuseipdb.com/api/v2/check"


class AbuseIPDBProvider(BaseProvider):
    name = "AbuseIPDB"
    categories = ("ip",)
    requires_key = True

    def _query(self, ioc: str, ioc_type: IOCType) -> ProviderResult:
        resp = self.session.get(
            API_URL,
            headers={"Key": self.api_key, "Accept": "application/json"},
            params={"ipAddress": ioc, "maxAgeInDays": 90},
            timeout=self.timeout,
        )
        if resp.status_code == 401:
            return self._error(ioc, "invalid API key (401)")
        if resp.status_code == 429:
            return self._error(ioc, "rate limit exceeded (429)")
        resp.raise_for_status()

        data = resp.json().get("data", {})
        score = int(data.get("abuseConfidenceScore", 0))
        reports = int(data.get("totalReports", 0))

        if score >= 50:
            verdict = Verdict.MALICIOUS
        elif score > 0 or reports > 0:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.CLEAN

        return ProviderResult(
            provider=self.name,
            ioc=ioc,
            success=True,
            verdict=verdict,
            summary=f"{score}% abuse confidence, {reports} reports",
            details={
                "abuseConfidenceScore": score,
                "totalReports": reports,
                "countryCode": data.get("countryCode"),
                "isp": data.get("isp"),
                "domain": data.get("domain"),
                "isTor": data.get("isTor"),
            },
            link=f"https://www.abuseipdb.com/check/{ioc}",
        )
