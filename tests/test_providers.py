"""Provider, enrichment, CLI and report tests with a mocked HTTP layer (no network)."""

import json

import pytest
import requests

from ioc_hunter.cli import main
from ioc_hunter.enrich import Enricher, build_providers
from ioc_hunter.models import IOCType, Verdict
from ioc_hunter.providers import AbuseIPDBProvider, OTXProvider, VirusTotalProvider
from ioc_hunter.providers.base import BaseProvider
from ioc_hunter.report import to_html, to_json


class FakeResponse:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"{self.status_code} error")


def _fake(provider, response=None, exc=None):
    """Replace provider.session.get; returns the list of recorded calls."""
    calls = []

    def get(url, **kwargs):
        calls.append((url, kwargs))
        if exc is not None:
            raise exc
        return response

    provider.session.get = get
    return calls


# --- VirusTotal ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("stats", "verdict"),
    [
        ({"malicious": 5, "suspicious": 0, "harmless": 60, "undetected": 10}, Verdict.MALICIOUS),
        ({"malicious": 1, "suspicious": 0, "harmless": 60, "undetected": 10}, Verdict.SUSPICIOUS),
        ({"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 10}, Verdict.CLEAN),
        ({}, Verdict.UNKNOWN),
    ],
)
def test_virustotal_verdicts(stats, verdict):
    vt = VirusTotalProvider(api_key="k")
    payload = {"data": {"attributes": {"last_analysis_stats": stats}}}
    calls = _fake(vt, FakeResponse(200, payload))
    result = vt.query("8.8.8.8", IOCType.IPV4)
    assert result.success and result.verdict is verdict
    url, kwargs = calls[0]
    assert url.endswith("/ip_addresses/8.8.8.8")
    assert kwargs["headers"] == {"x-apikey": "k"}
    assert "k" not in url  # key travels in a header, never in the URL


def test_virustotal_url_id_is_unpadded_base64():
    vt = VirusTotalProvider(api_key="k")
    calls = _fake(vt, FakeResponse(404))
    result = vt.query("https://evil.com/login#tok", IOCType.URL)
    assert result.success and result.verdict is Verdict.UNKNOWN
    assert "=" not in calls[0][0].rsplit("/", 1)[1]


@pytest.mark.parametrize(
    ("provider_cls", "status", "message"),
    [
        (VirusTotalProvider, 401, "invalid API key (401)"),
        (VirusTotalProvider, 429, "rate limit exceeded (429)"),
        (AbuseIPDBProvider, 401, "invalid API key (401)"),
        (AbuseIPDBProvider, 429, "rate limit exceeded (429)"),
        (OTXProvider, 403, "invalid API key (403)"),
        (OTXProvider, 429, "rate limit exceeded (429)"),
    ],
)
def test_auth_and_rate_limit_errors(provider_cls, status, message):
    provider = provider_cls(api_key="k")
    _fake(provider, FakeResponse(status))
    result = provider.query("8.8.8.8", IOCType.IPV4)
    assert not result.success
    assert result.verdict is Verdict.ERROR
    assert result.error == message


def test_timeout_and_network_errors_are_contained():
    vt = VirusTotalProvider(api_key="k")
    _fake(vt, exc=requests.exceptions.Timeout())
    assert vt.query("8.8.8.8", IOCType.IPV4).error == "request timed out"
    _fake(vt, exc=requests.exceptions.ConnectionError("refused"))
    assert vt.query("8.8.8.8", IOCType.IPV4).error.startswith("network error")
    _fake(vt, FakeResponse(500))
    assert vt.query("8.8.8.8", IOCType.IPV4).verdict is Verdict.ERROR


def test_missing_key_skips_without_request():
    vt = VirusTotalProvider(api_key=None)
    calls = _fake(vt, FakeResponse(200))
    result = vt.query("8.8.8.8", IOCType.IPV4)
    assert result.error == "no API key configured (skipped)"
    assert calls == []


# --- AbuseIPDB / OTX ------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "reports", "verdict"),
    [(80, 12, Verdict.MALICIOUS), (10, 1, Verdict.SUSPICIOUS), (0, 0, Verdict.CLEAN)],
)
def test_abuseipdb_verdicts(score, reports, verdict):
    ab = AbuseIPDBProvider(api_key="k")
    payload = {"data": {"abuseConfidenceScore": score, "totalReports": reports}}
    calls = _fake(ab, FakeResponse(200, payload))
    result = ab.query("185.220.101.1", IOCType.IPV4)
    assert result.verdict is verdict
    assert calls[0][1]["headers"]["Key"] == "k"
    assert calls[0][1]["params"]["ipAddress"] == "185.220.101.1"


def test_abuseipdb_only_supports_ips():
    ab = AbuseIPDBProvider(api_key="k")
    assert ab.supports(IOCType.IPV4) and ab.supports(IOCType.IPV6)
    assert not ab.supports(IOCType.DOMAIN)


@pytest.mark.parametrize(("count", "verdict"), [(5, Verdict.MALICIOUS), (1, Verdict.SUSPICIOUS), (0, Verdict.CLEAN)])
def test_otx_verdicts(count, verdict):
    otx = OTXProvider(api_key="k")
    payload = {"pulse_info": {"count": count, "pulses": [{"name": "APT test"}] * count}}
    calls = _fake(otx, FakeResponse(200, payload))
    result = otx.query("evil.com", IOCType.DOMAIN)
    assert result.verdict is verdict
    assert "/domain/evil.com/general" in calls[0][0]


def test_otx_not_found():
    otx = OTXProvider(api_key="k")
    _fake(otx, FakeResponse(404))
    result = otx.query("d41d8cd98f00b204e9800998ecf8427e", IOCType.MD5)
    assert result.success and result.summary == "no OTX data"


# --- Enricher: internal indicators never leave the network -------------------


class RecordingProvider(BaseProvider):
    name = "Recorder"
    categories = ("ip", "domain", "url", "hash")
    requires_key = False

    def __init__(self):
        super().__init__()
        self.seen = []

    def _query(self, ioc, ioc_type):
        self.seen.append(ioc)
        from ioc_hunter.models import ProviderResult

        return ProviderResult(self.name, ioc, success=True, verdict=Verdict.CLEAN)


INTERNAL = [
    "10.1.2.3",
    "192.168.0.10",
    "172.16.5.4",
    "127.0.0.1",
    "169.254.1.1",
    "100.64.0.1",
    "fd00::1",
    "fileserver.corp.local",
    "db01.internal",
    "https://intranet.lan/login",
    "http://10.0.0.5:8080/admin",
]
EXTERNAL = [
    "8.8.8.8",
    "2001:4860:4860::8888",
    "evil.com",
    "malware-c2.example",
    "https://evil.com/login#token",
    "d41d8cd98f00b204e9800998ecf8427e",
]


def test_internal_indicators_are_not_sent():
    rec = RecordingProvider()
    reports = Enricher([rec]).enrich_many(INTERNAL + EXTERNAL)
    assert rec.seen == EXTERNAL
    for report in reports[: len(INTERNAL)]:
        assert report.results == []
        assert report.note.startswith("not queried:")
        assert report.verdict is Verdict.UNKNOWN


def test_allow_internal_sends_everything():
    rec = RecordingProvider()
    Enricher([rec], allow_internal=True).enrich_many(INTERNAL)
    assert rec.seen == INTERNAL


# --- CLI / reports ------------------------------------------------------------


def test_cli_json_demo_skips_internal(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    code = main(["--demo", "--json", "10.1.2.3", "hxxps://evil[.]com/x#frag"])
    out = json.loads(capsys.readouterr().out)
    by_ioc = {r["ioc"]: r for r in out["reports"]}
    assert by_ioc["10.1.2.3"]["note"].startswith("not queried: private/non-routable IP")
    assert by_ioc["10.1.2.3"]["results"] == []
    assert by_ioc["https://evil.com/x#frag"]["results"]  # fragment kept, queried
    assert code in (0, 1)


def test_cli_allow_internal_flag(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    main(["--demo", "--json", "--allow-internal", "10.1.2.3"])
    out = json.loads(capsys.readouterr().out)
    assert out["reports"][0]["results"]
    assert out["reports"][0]["note"] is None


def test_cli_reads_file_with_comments(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    f = tmp_path / "iocs.txt"
    f.write_text("# header\n8.8.8.8  # google dns\nhttps://evil.com/a#b\n")
    main(["--demo", "--json", "-f", str(f)])
    out = json.loads(capsys.readouterr().out)
    assert [r["ioc"] for r in out["reports"]] == ["8.8.8.8", "https://evil.com/a#b"]


def test_cli_no_iocs_is_an_error(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    assert main([]) == 2


def test_html_report_escapes_and_shows_note():
    rec = RecordingProvider()
    reports = Enricher([rec]).enrich_many(["<script>x</script>.com", "10.0.0.1"])
    page = to_html(reports)
    assert "<script>x</script>" not in page
    assert "not queried: private/non-routable IP" in page
    assert json.loads(to_json(reports))["count"] == 2


def test_build_providers_reads_env(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "abc")
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    providers = {p.name: p for p in build_providers()}
    assert providers["VirusTotal"].enabled
    assert not providers["AlienVault OTX"].enabled
    assert [p.name for p in build_providers(selected=["otx"])] == ["AlienVault OTX"]
