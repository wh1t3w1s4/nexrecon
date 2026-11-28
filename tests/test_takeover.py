from __future__ import annotations

from nexrecon.http_client import FetchResult
from nexrecon.models import Confidence, Severity
from nexrecon.modules import takeover


class FakeClient:
    def __init__(self, responses=None):
        self._responses = responses or {}
        self.calls: list[str] = []

    def get(self, url, **_):
        self.calls.append(url)
        body = self._responses.get(url)
        if body is None:
            return FetchResult(ok=False, error="connection refused")
        return FetchResult(ok=True, status_code=200, headers={}, text=body)


def test_no_cname_means_no_finding(monkeypatch):
    monkeypatch.setattr(takeover.dns_recon, "resolve_cname", lambda h, **_: None)
    assert takeover.check_host(FakeClient(), "sub.example.com") is None


def test_cname_to_unknown_service_no_finding(monkeypatch):
    monkeypatch.setattr(takeover.dns_recon, "resolve_cname", lambda h, **_: "cdn.unknown-vendor.net")
    assert takeover.check_host(FakeClient(), "sub.example.com") is None


def test_dangling_cname_is_certain_high(monkeypatch):
    monkeypatch.setattr(takeover.dns_recon, "resolve_cname", lambda h, **_: "ghost.github.io")
    monkeypatch.setattr(takeover.dns_recon, "resolves", lambda h, **_: False)
    client = FakeClient()  # no debería ni llegar a pedir HTTP
    finding = takeover.check_host(client, "sub.example.com")
    assert finding is not None
    assert finding.severity == Severity.HIGH
    assert finding.confidence == Confidence.CERTAIN
    assert "github.io" in finding.detail
    assert client.calls == []  # NXDOMAIN ya es concluyente, no hace falta HTTP


def test_live_cname_with_fingerprint_is_certain(monkeypatch):
    monkeypatch.setattr(takeover.dns_recon, "resolve_cname", lambda h, **_: "x.herokudns.com")
    monkeypatch.setattr(takeover.dns_recon, "resolves", lambda h, **_: True)
    client = FakeClient({"https://sub.example.com": "<html>No such app</html>"})
    finding = takeover.check_host(client, "sub.example.com")
    assert finding is not None
    assert finding.confidence == Confidence.CERTAIN
    assert "No such app" in finding.detail


def test_live_cname_no_fingerprint_no_finding(monkeypatch):
    monkeypatch.setattr(takeover.dns_recon, "resolve_cname", lambda h, **_: "x.herokudns.com")
    monkeypatch.setattr(takeover.dns_recon, "resolves", lambda h, **_: True)
    client = FakeClient({"https://sub.example.com": "<html>Bienvenido a mi app</html>"})
    assert takeover.check_host(client, "sub.example.com") is None


def test_non_vulnerable_service_gets_firm_not_certain(monkeypatch):
    monkeypatch.setattr(takeover.dns_recon, "resolve_cname", lambda h, **_: "shop.myshopify.com")
    monkeypatch.setattr(takeover.dns_recon, "resolves", lambda h, **_: True)
    client = FakeClient({"https://sub.example.com": "Sorry, this shop is currently unavailable"})
    finding = takeover.check_host(client, "sub.example.com")
    assert finding is not None
    assert finding.confidence == Confidence.FIRM


def test_https_failure_falls_back_to_http(monkeypatch):
    monkeypatch.setattr(takeover.dns_recon, "resolve_cname", lambda h, **_: "x.github.io")
    monkeypatch.setattr(takeover.dns_recon, "resolves", lambda h, **_: True)
    client = FakeClient({"http://sub.example.com": "There isn't a GitHub Pages site here"})
    finding = takeover.check_host(client, "sub.example.com")
    assert finding is not None
    assert client.calls == ["https://sub.example.com", "http://sub.example.com"]
