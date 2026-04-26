import pytest
from ioc_enricher.utils import detect_ioc_type
from ioc_enricher.models import IOCType


@pytest.mark.parametrize("value,expected", [
    ("8.8.8.8", IOCType.IP),
    ("2001:4860:4860::8888", IOCType.IP),
    ("malware.bazaar.abuse.ch", IOCType.DOMAIN),
    ("example.com", IOCType.DOMAIN),
    ("d41d8cd98f00b204e9800998ecf8427e", IOCType.HASH),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", IOCType.HASH),
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", IOCType.HASH),
    ("not-an-ioc!!!", IOCType.UNKNOWN),
    ("", IOCType.UNKNOWN),
])
def test_detect_ioc_type(value, expected):
    assert detect_ioc_type(value) == expected
