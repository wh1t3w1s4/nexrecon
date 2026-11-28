from __future__ import annotations

import json

from nexrecon.http_client import FetchResult
from nexrecon.models import HostResult, Severity
from nexrecon.modules import osv

JQUERY_1_7_RESPONSE = json.dumps({
    "vulns": [
        {
            "id": "GHSA-gxr4-xjj5-5px2",
            "aliases": ["CVE-2015-9251"],
            "summary": "jQuery XSS vulnerability",
            "details": "detalle largo " * 20,
            "severity": [{"type": "CVSS_V3", "score": "6.1"}],
            "affected": [{"ranges": [{"type": "SEMVER", "events": [
                {"introduced": "0"}, {"fixed": "1.9.0"},
            ]}]}],
            "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2015-9251"}],
        },
    ],
})


class FakeOsvClient:
    def __init__(self, response_text=None, ok=True, status_code=200, calls=None):
        self._response_text = response_text
        self._ok = ok
        self._status_code = status_code
        self.calls = calls if calls is not None else []

    def request(self, method, url, json_body=None, timeout=None, **_):
        self.calls.append({"method": method, "url": url, "json_body": json_body})
        return FetchResult(ok=self._ok, status_code=self._status_code,
                           headers={}, text=self._response_text or "")


def test_query_osv_parses_cve_fixed_in_and_cvss():
    client = FakeOsvClient(response_text=JQUERY_1_7_RESPONSE)
    results = osv.query_osv(client, "npm", "jquery", "1.7.0")
    assert len(results) == 1
    v = results[0]
    assert v.cve == "CVE-2015-9251"
    assert v.fixed_in == "1.9.0"
    assert v.cvss == "6.1"
    assert "nvd.nist.gov" in v.reference


def test_query_osv_sends_correct_request_body():
    client = FakeOsvClient(response_text='{"vulns": []}')
    osv.query_osv(client, "npm", "jquery", "1.7.0")
    assert client.calls[0]["method"] == "POST"
    assert client.calls[0]["json_body"] == {
        "version": "1.7.0", "package": {"name": "jquery", "ecosystem": "npm"},
    }


def test_query_osv_network_failure_returns_empty():
    client = FakeOsvClient(ok=False)
    assert osv.query_osv(client, "npm", "jquery", "1.7.0") == []


def test_query_osv_bad_json_returns_empty():
    client = FakeOsvClient(response_text="no es json")
    assert osv.query_osv(client, "npm", "jquery", "1.7.0") == []


def test_query_osv_non_200_returns_empty():
    client = FakeOsvClient(response_text=JQUERY_1_7_RESPONSE, status_code=500)
    assert osv.query_osv(client, "npm", "jquery", "1.7.0") == []


def test_enrich_dedups_against_static_cves(monkeypatch):
    client = FakeOsvClient(response_text=JQUERY_1_7_RESPONSE)
    host = HostResult(hostname="t.example")
    host.technologies = {"jQuery": "1.7.0"}

    matches = osv.enrich(client, host, static_cves={"CVE-2015-9251"})
    assert matches == []
    assert not any(f.module == "osv" for f in host.findings)


def test_enrich_adds_new_vuln_not_in_static_cves():
    client = FakeOsvClient(response_text=JQUERY_1_7_RESPONSE)
    host = HostResult(hostname="t.example")
    host.technologies = {"jQuery": "1.7.0"}

    matches = osv.enrich(client, host, static_cves=set())
    assert len(matches) == 1
    assert matches[0].source == "osv"
    assert matches[0].cve == "CVE-2015-9251"
    findings = [f for f in host.findings if f.module == "osv"]
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_enrich_skips_unmapped_technology():
    client = FakeOsvClient(response_text=JQUERY_1_7_RESPONSE)
    host = HostResult(hostname="t.example")
    host.technologies = {"nginx": "1.18.0"}  # sin entrada en OSV_ECOSYSTEM_MAP

    matches = osv.enrich(client, host, static_cves=set())
    assert matches == []
    assert client.calls == []


def test_enrich_skips_technology_without_version():
    client = FakeOsvClient(response_text=JQUERY_1_7_RESPONSE)
    host = HostResult(hostname="t.example")
    host.technologies = {"jQuery": ""}

    matches = osv.enrich(client, host, static_cves=set())
    assert matches == []
    assert client.calls == []


def test_cache_avoids_repeated_network_calls(monkeypatch):
    monkeypatch.setattr(osv, "_cache", {})
    client = FakeOsvClient(response_text=JQUERY_1_7_RESPONSE)
    host1 = HostResult(hostname="a.example")
    host1.technologies = {"jQuery": "1.7.0"}
    host2 = HostResult(hostname="b.example")
    host2.technologies = {"jQuery": "1.7.0"}

    osv.enrich(client, host1, static_cves=set())
    osv.enrich(client, host2, static_cves=set())
    assert len(client.calls) == 1
