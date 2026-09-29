"""Offline unit tests — no network, safe for CI."""

from ioc_hunter.models import IOCType, Verdict, IOCReport, ProviderResult
from ioc_hunter.utils import detect_type, refang, parse_iocs


def test_detect_ipv4():
    assert detect_type("8.8.8.8") is IOCType.IPV4


def test_detect_ipv6():
    assert detect_type("2001:4860:4860::8888") is IOCType.IPV6


def test_detect_domain():
    assert detect_type("example.com") is IOCType.DOMAIN


def test_detect_url():
    assert detect_type("https://example.com/path") is IOCType.URL


def test_detect_hashes():
    assert detect_type("d41d8cd98f00b204e9800998ecf8427e") is IOCType.MD5
    assert detect_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") is IOCType.SHA1
    assert detect_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is IOCType.SHA256


def test_detect_unknown():
    assert detect_type("not an ioc!!") is IOCType.UNKNOWN


def test_refang():
    assert refang("hxxps://evil[.]com") == "https://evil.com"
    assert refang("1.2.3[.]4") == "1.2.3.4"


def test_category():
    assert IOCType.IPV4.category == "ip"
    assert IOCType.SHA256.category == "hash"
    assert IOCType.DOMAIN.category == "domain"


def test_parse_iocs_dedup_and_comments():
    raw = ["8.8.8.8", "# a comment", "8.8.8.8", "evil[.]com  1.1.1.1"]
    parsed = parse_iocs(raw)
    assert parsed == ["8.8.8.8", "evil.com", "1.1.1.1"]


def test_verdict_ordering():
    assert Verdict.MALICIOUS.level > Verdict.SUSPICIOUS.level > Verdict.CLEAN.level


def test_report_aggregates_worst_verdict():
    report = IOCReport(ioc="x", ioc_type=IOCType.IPV4)
    report.results.append(ProviderResult("A", "x", success=True, verdict=Verdict.CLEAN))
    report.results.append(ProviderResult("B", "x", success=True, verdict=Verdict.MALICIOUS))
    assert report.verdict is Verdict.MALICIOUS
    assert report.malicious_sources == 1
    assert report.checked_sources == 2


def test_parse_iocs_keeps_url_fragments():
    raw = ["https://evil.com/login#session=abc", "hxxps://evil[.]com/p#x  # note"]
    assert parse_iocs(raw) == ["https://evil.com/login#session=abc", "https://evil.com/p#x"]


def test_parse_iocs_inline_comment_after_whitespace():
    assert parse_iocs(["8.8.8.8 # dns", "\t# indented comment", "1.1.1.1\t#tab"]) == [
        "8.8.8.8",
        "1.1.1.1",
    ]


def test_internal_reason():
    from ioc_hunter.utils import internal_reason

    assert internal_reason("10.0.0.1", IOCType.IPV4) == "private/non-routable IP"
    assert internal_reason("::1", IOCType.IPV6) == "private/non-routable IP"
    assert internal_reason("nas.home.arpa", IOCType.DOMAIN) == "internal hostname"
    assert internal_reason("http://192.168.1.1/", IOCType.URL) == "private/non-routable IP"
    assert internal_reason("8.8.8.8", IOCType.IPV4) is None
    assert internal_reason("evil.example", IOCType.DOMAIN) is None
    assert internal_reason("d41d8cd98f00b204e9800998ecf8427e", IOCType.MD5) is None
