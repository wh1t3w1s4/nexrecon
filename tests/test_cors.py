from __future__ import annotations

from nexrecon.http_client import FetchResult
from nexrecon.models import Confidence, HostResult, Severity
from nexrecon.modules import cors

BASE = "https://t.example"


class FakeClient:
    def __init__(self, by_origin: dict[str, dict[str, str]]):
        """`by_origin`: {origin enviado -> headers de respuesta}."""
        self._by_origin = by_origin
        self.calls: list[str] = []

    def get(self, url, headers=None, **_):
        origin = (headers or {}).get("Origin", "")
        self.calls.append(origin)
        resp_headers = self._by_origin.get(origin)
        if resp_headers is None:
            return FetchResult(ok=False, error="sin respuesta configurada")
        return FetchResult(ok=True, status_code=200, headers=resp_headers, text="")


def host():
    return HostResult(hostname="t.example")


def test_reflected_origin_with_credentials_is_critical_certain():
    client = FakeClient({
        cors._EVIL_ORIGIN: {"Access-Control-Allow-Origin": cors._EVIL_ORIGIN,
                            "Access-Control-Allow-Credentials": "true"},
        "null": {},
    })
    findings = cors.check(client, host(), BASE)
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(crit) == 1
    assert crit[0].confidence == Confidence.CERTAIN
    assert "reflejado con credenciales" in crit[0].title


def test_reflected_origin_without_credentials_is_medium_firm():
    client = FakeClient({
        cors._EVIL_ORIGIN: {"Access-Control-Allow-Origin": cors._EVIL_ORIGIN},
        "null": {},
    })
    findings = cors.check(client, host(), BASE)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].confidence == Confidence.FIRM


def test_wildcard_without_credentials_is_low():
    client = FakeClient({
        cors._EVIL_ORIGIN: {"Access-Control-Allow-Origin": "*"},
        "null": {},
    })
    findings = cors.check(client, host(), BASE)
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW


def test_null_origin_with_credentials_is_high():
    client = FakeClient({
        cors._EVIL_ORIGIN: {},
        "null": {"Access-Control-Allow-Origin": "null", "Access-Control-Allow-Credentials": "true"},
    })
    findings = cors.check(client, host(), BASE)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "null" in findings[0].title


def test_no_cors_headers_no_findings():
    client = FakeClient({cors._EVIL_ORIGIN: {}, "null": {}})
    assert cors.check(client, host(), BASE) == []


def test_sends_exactly_the_two_expected_origins():
    client = FakeClient({cors._EVIL_ORIGIN: {}, "null": {}})
    cors.check(client, host(), BASE)
    assert set(client.calls) == {cors._EVIL_ORIGIN, "null"}


def test_connection_failure_returns_no_findings_not_an_exception():
    client = FakeClient({})  # ninguna respuesta configurada -> ok=False siempre
    assert cors.check(client, host(), BASE) == []
