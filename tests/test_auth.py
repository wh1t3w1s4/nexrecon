import pytest
import requests

from nexrecon.auth import AuthContext, parse_cookie_header, redact_text
from nexrecon.http_client import HttpClient


def test_parse_ok():
    assert parse_cookie_header("A=1; B=x=y ;") == {"A": "1", "B": "x=y"}


@pytest.mark.parametrize("bad", ["", " ; ", "sinvalor", "=v", "A=1\r\nX: y"])
def test_parse_invalid(bad):
    with pytest.raises(ValueError):
        parse_cookie_header(bad)


def test_repr_does_not_leak_values():
    assert "SECRET" not in repr(AuthContext({"S": "SECRETVALUE"}))


def test_redact_set_cookie_only_our_cookies():
    auth = AuthContext({"PHPSESSID": "abcdef"})
    assert auth.redact_set_cookie("PHPSESSID=abcdef; Path=/; Secure") == "PHPSESSID=[REDACTED]; Path=/; Secure"
    assert auth.redact_set_cookie("other=zzz; Path=/") == "other=zzz; Path=/"


def test_redact_text_skips_short_values():

    assert "abcdef" not in redact_text("token=abcdef", ["abcdef"])
    assert AuthContext({"n": "1"}).secrets() == []


def test_client_requires_scope():
    with pytest.raises(ValueError):
        HttpClient(auth=AuthContext({"A": "1"}))


@pytest.mark.parametrize("scope,url,expected", [
    ("example.com", "https://www.example.com/", True),
    ("example.com", "https://example.com.evil.net/", False),
    ("example.com", "https://evil-example.com/", False),
    ("example.com", "https://crt.sh/", False),
    ("lab.test:8080", "http://lab.test:8080/x", True),
    ("10.10.11.5:8080", "http://10.10.11.5:8080/", True),
    ("localhost", "http://localhost:8000/", True),
])
def test_cookie_scoped_to_target(scope, url, expected):
    client = HttpClient(auth=AuthContext({"S": "abcd1234"}), scope_domain=scope)
    req = client._session().prepare_request(requests.Request("GET", url))
    assert ("Cookie" in req.headers) is expected
