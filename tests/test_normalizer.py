import pytest
from app.services.normalizer import normalizer
from app.models.indicator import IndicatorType


def test_valid_ipv4():
    res = normalizer.normalize("192.168.1.1")
    assert res.indicator_type == IndicatorType.IP
    assert res.normalized == "192.168.1.1"
    assert res.redis_key == "ti:ip:192.168.1.1"
    assert res.ip_version == 4


def test_valid_ipv6():
    res = normalizer.normalize("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
    assert res.indicator_type == IndicatorType.IP
    assert res.normalized == "2001:db8:85a3::8a2e:370:7334"
    assert res.redis_key == "ti:ip:2001:db8:85a3::8a2e:370:7334"
    assert res.ip_version == 6


def test_valid_domain():
    res = normalizer.normalize("EXAMPLE.COM")
    assert res.indicator_type == IndicatorType.DOMAIN
    assert res.normalized == "example.com"
    assert res.redis_key == "ti:domain:example.com"


def test_valid_domain_with_subdomain():
    res = normalizer.normalize("phish.secure-login.bank.co.uk.")
    assert res.indicator_type == IndicatorType.DOMAIN
    assert res.normalized == "phish.secure-login.bank.co.uk"
    assert res.redis_key == "ti:domain:phish.secure-login.bank.co.uk"


def test_valid_url():
    raw = "HTTP://Example.COM:80/path/to/FILE?query=1&b=2#section"
    res = normalizer.normalize(raw)
    assert res.indicator_type == IndicatorType.URL
    # Default port 80 stripped, scheme/host lowercased, path preserved, fragment stripped
    assert res.normalized == "http://example.com/path/to/FILE?query=1&b=2"
    assert res.lookup_hash is not None
    assert res.redis_key.startswith("ti:url:")
    assert len(res.redis_key) == 7 + 64  # "ti:url:" + 64-char sha256


def test_invalid_indicators():
    invalid_cases = [
        "",
        "   ",
        "invalid..domain..name",
        "ftp://malicious.com",
        "999.999.999.999",
        "2001:xyz::1",
        "hello world with spaces",
        "evil\r\nindicator",
    ]
    for case in invalid_cases:
        with pytest.raises(ValueError):
            normalizer.normalize(case)
