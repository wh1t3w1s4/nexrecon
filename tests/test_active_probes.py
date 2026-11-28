import argparse

import pytest

from nexrecon.http_client import FetchResult
from nexrecon.models import Endpoint, Severity
from nexrecon.modules import active_probes as ap


class FakeClient:
    """Simula un HttpClient: `responder(method, url, params)` decide la
    respuesta según los parámetros que llegarían realmente (vía query o
    data), igual que un servidor real reaccionando al payload.
    """
    def __init__(self, responder, auth=None):
        self.auth = auth
        self._responder = responder
        self.calls: list[dict] = []

    def request(self, method, url, params=None, **_):
        self.calls.append({"method": method, "url": url, "params": params})
        return self._responder(method, url, params or {})

    def post(self, url, data=None, **_):
        self.calls.append({"method": "POST", "url": url, "params": data})
        return self._responder("POST", url, data or {})


def ep(params, method="GET", hidden=None):
    return Endpoint(url="https://t.example/search", method=method,
                    params=params, source="manual", hidden=hidden or [])


def ok(text="normal response", status=200):
    return FetchResult(ok=True, status_code=status, headers={}, text=text)


# --------------------------------------------------------------- SQLi

def test_sqli_detected_on_new_db_error():
    def responder(method, url, params):
        if params.get("q", "").endswith("'"):
            return ok("You have an error in your SQL syntax near ''' at line 1")
        return ok("results: none")
    client = FakeClient(responder)
    findings = ap.probe_endpoint(client, ep({"q": "x"}), authenticated=False)
    titles = [f.title for f in findings]
    assert any("SQLi" in t for t in titles)
    assert findings[[("SQLi" in t) for t in titles].index(True)].severity == Severity.HIGH


def test_sqli_not_flagged_when_error_present_in_baseline_too():
    def responder(method, url, params):
        return ok("sql syntax error always shown, buggy app")
    client = FakeClient(responder)
    findings = ap.probe_endpoint(client, ep({"q": "x"}), authenticated=False)
    assert not any("SQLi" in f.title for f in findings)


# --------------------------------------------------------------- XSS

def test_xss_detected_on_unescaped_reflection():
    def responder(method, url, params):
        value = params.get("q", "")
        return ok(f"<div>Resultados para: {value}</div>")  # eco sin escapar
    client = FakeClient(responder)
    findings = ap.probe_endpoint(client, ep({"q": "x"}), authenticated=False)
    assert any("XSS" in f.title and f.severity == Severity.HIGH for f in findings)


def test_xss_not_flagged_when_html_escaped():
    def responder(method, url, params):
        value = params.get("q", "")
        escaped = value.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")
        return ok(f"<div>Resultados para: {escaped}</div>")
    client = FakeClient(responder)
    findings = ap.probe_endpoint(client, ep({"q": "x"}), authenticated=False)
    assert not any("XSS" in f.title for f in findings)


# --------------------------------------------------------------- SSTI

def test_ssti_detected_needs_both_expressions():
    def responder(method, url, params):
        value = params.get("name", "")
        if "{{7*7}}" in value:
            return ok("hola 49")
        if "{{8*8}}" in value:
            return ok("hola 64")
        return ok("hola {{7*7}}")  # baseline: sin evaluar
    client = FakeClient(responder)
    findings = ap.probe_endpoint(client, ep({"name": "x"}), authenticated=False)
    assert any(f.title.startswith("Posible SSTI") and f.severity == Severity.CRITICAL for f in findings)


def test_ssti_falls_through_to_erb_when_jinja_does_not_evaluate():
    # El target usa ERB, no Jinja2/Twig — {{7*7}} se refleja tal cual (no
    # evalúa) pero <%= 7*7 %> sí. No debe quedarse en el primer estilo.
    def responder(method, url, params):
        value = params.get("name", "")
        if "<%= 7*7 %>" in value:
            return ok("hola 49")
        if "<%= 8*8 %>" in value:
            return ok("hola 64")
        return ok(f"hola {value}")  # Jinja2/Freemarker: eco literal, sin evaluar
    client = FakeClient(responder)
    findings = ap.probe_endpoint(client, ep({"name": "x"}), authenticated=False)
    ssti = [f for f in findings if f.title.startswith("Posible SSTI")]
    assert len(ssti) == 1 and "<%= 7*7 %>" in ssti[0].detail


def test_ssti_false_positive_avoided_when_second_expression_fails():
    def responder(method, url, params):
        value = params.get("name", "")
        if "{{7*7}}" in value:
            return ok("un texto que casualmente contiene 49 por otra razón")
        return ok("un texto sin nada especial")
    client = FakeClient(responder)
    findings = ap.probe_endpoint(client, ep({"name": "x"}), authenticated=False)
    assert not any(f.title.startswith("Posible SSTI") for f in findings)


# --------------------------------------------------------------- IDOR

def test_idor_detected_on_different_200_body():
    bodies = {"1": ok("factura de Alice"), "2": ok("factura de Bob")}

    def responder(method, url, params):
        return bodies.get(params.get("invoice_id"), ok("not found", 404))
    client = FakeClient(responder)
    findings = ap.probe_endpoint(client, ep({"invoice_id": "1"}), authenticated=False)
    idor = [f for f in findings if "IDOR" in f.title]
    assert len(idor) == 1 and idor[0].severity == Severity.MEDIUM


def test_idor_severity_high_when_authenticated():
    bodies = {"1": ok("factura de Alice"), "2": ok("factura de Bob")}

    def responder(method, url, params):
        return bodies.get(params.get("invoice_id"), ok("not found", 404))
    client = FakeClient(responder, auth=object())
    findings = ap.probe_endpoint(client, ep({"invoice_id": "1"}), authenticated=True)
    idor = [f for f in findings if "IDOR" in f.title]
    assert idor[0].severity == Severity.HIGH


def test_idor_not_flagged_on_access_denied():
    def responder(method, url, params):
        if params.get("invoice_id") == "2":
            return ok("Acceso denegado a este recurso")
        return ok("factura de Alice")
    client = FakeClient(responder)
    findings = ap.probe_endpoint(client, ep({"invoice_id": "1"}), authenticated=False)
    assert not any("IDOR" in f.title for f in findings)


def test_idor_skips_non_id_or_hidden_params():
    def responder(method, url, params):
        return ok(f"body-{params}")
    client = FakeClient(responder)
    findings = ap.probe_endpoint(
        client, ep({"invoice_id": "1", "csrf": "1"}, hidden=["csrf"]), authenticated=False,
    )
    assert not any("IDOR" in f.title and "csrf" in f.detail for f in findings)


# --------------------------------------------------------------- SSRF (estático, sin red)

def test_ssrf_candidate_by_value_and_by_name_no_requests_sent():
    # `_probe_ssrf_candidates` es puramente estático (sin payload activo);
    # se prueba aislado, sin cliente, para dejar eso explícito.
    endpoint = ep({"callback": "x", "redirect_url": "https://internal.local/x", "q": "normal"})
    findings = ap._probe_ssrf_candidates(endpoint)
    titles = {f.title: f.severity for f in findings}
    assert any("callback" in t for t in titles)
    assert any("redirect_url" in t and sev == Severity.LOW for t, sev in titles.items())
    assert not any("'q'" in t for t in titles)


def test_ssrf_candidate_detected_even_in_hidden_field():
    # Caso real: PortSwigger pone el candidato típico (`stockApi`) en un
    # <input type="hidden">. Como esto no manda ninguna petición, SÍ debe
    # revisarse (a diferencia de SQLi/XSS/SSTI/IDOR, que sí se saltan hidden).
    endpoint = ep(
        {"stockApi": "http://localhost/product/stock/check?productId=1&storeId=1"},
        hidden=["stockApi"],
    )
    findings = ap._probe_ssrf_candidates(endpoint)
    assert len(findings) == 1 and "stockApi" in findings[0].title
    assert findings[0].severity == Severity.LOW


# ----------------------------------------------------------- manual / argparse

def test_argparse_param_builds_endpoint():
    result = ap.argparse_param("https://target.com/search?q=")
    assert result.url == "https://target.com/search" and result.params == {"q": ""}


def test_argparse_param_rejects_url_without_params():
    with pytest.raises(argparse.ArgumentTypeError):
        ap.argparse_param("https://target.com/search")


@pytest.mark.parametrize("bad", ["/filter?category=", "filter?category=", "filter?category=Pets"])
def test_argparse_param_rejects_relative_urls(bad):
    # Antes se aceptaban en silencio y luego fallaban sin aviso en cada
    # petición real, dando "sin hallazgos" sin pista de qué pasó.
    with pytest.raises(argparse.ArgumentTypeError):
        ap.argparse_param(bad)


def test_argparse_param_warns_on_likely_shell_escape_mistake(capsys):
    # El valor sigue siendo una URL "válida" tal cual (con backslashes
    # literales), así que no debe fallar — solo avisar por stderr.
    result = ap.argparse_param(r"https://target.com/filter\?category\=Gifts")
    assert result.params  # no lanza, solo avisa
    assert "\\?" in capsys.readouterr().err


def test_argparse_param_no_warning_for_normal_url(capsys):
    ap.argparse_param("https://target.com/filter?category=Gifts")
    assert capsys.readouterr().err == ""


def test_baseline_failure_reports_diagnostic_not_silence():
    def responder(method, url, params):
        return FetchResult(ok=False, error="MissingSchema")
    client = FakeClient(responder)
    findings = ap.probe_endpoint(client, ep({"q": "x"}), authenticated=False)
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "No se pudo probar" in findings[0].title


def test_xss_variant_matches_even_if_compound_marker_would_be_escaped():
    # La app escapa comillas pero no los ángulos: la variante antigua
    # (comillas+ángulos en un solo marcador) se habría perdido esto.
    def responder(method, url, params):
        value = params.get("q", "").replace("'", "&#39;").replace('"', "&quot;")
        return ok(f"<div>{value}</div>")
    client = FakeClient(responder)
    findings = ap.probe_endpoint(client, ep({"q": "x"}), authenticated=False)
    assert any("XSS" in f.title for f in findings)


def test_run_manual_mode_targets_only_that_endpoint():
    calls = []

    def responder(method, url, params):
        calls.append(url)
        return ok("x")
    client = FakeClient(responder)
    from nexrecon.models import HostResult
    host = HostResult(hostname="target.com")
    host.endpoints = [ep({"other": "1"})]  # no debería tocarse en modo manual
    manual = ap.argparse_param("https://target.com/manual?z=")
    ap.run(client, host, manual=manual)
    assert all("manual" in c for c in calls)


def test_run_respects_max_endpoints_and_params_only_endpoints():
    host_endpoints = [ep({"a": "1"}) for _ in range(ap.MAX_ENDPOINTS + 5)]
    host_endpoints.append(Endpoint(url="https://t.example/no-params", method="GET", params={}, source="link"))
    from nexrecon.models import HostResult
    host = HostResult(hostname="t.example")
    host.endpoints = host_endpoints
    client = FakeClient(lambda *a, **k: ok("x"))
    ap.run(client, host)
    urls_hit = {c["url"] for c in client.calls}
    assert "https://t.example/no-params" not in urls_hit


# --------------------------------------------------------------- open redirect

def test_open_redirect_detected_on_redirect_param():
    def responder(method, url, params):
        if params.get("next", "").startswith("https://nxr-redirect.invalid"):
            return FetchResult(ok=True, status_code=302, headers={"Location": params["next"]}, text="")
        return ok("normal page")
    client = FakeClient(responder)
    findings = ap.probe_endpoint(client, ep({"next": "/home"}), authenticated=False)
    redirects = [f for f in findings if "Open redirect" in f.title]
    assert len(redirects) == 1
    assert redirects[0].severity == Severity.MEDIUM


def test_open_redirect_oauth_like_param_is_high():
    def responder(method, url, params):
        if "nxr-redirect.invalid" in params.get("redirect_uri", ""):
            return FetchResult(ok=True, status_code=302,
                               headers={"Location": params["redirect_uri"]}, text="")
        return ok("normal page")
    client = FakeClient(responder)
    findings = ap.probe_endpoint(client, ep({"redirect_uri": "/cb"}), authenticated=False)
    redirects = [f for f in findings if "Open redirect" in f.title]
    assert len(redirects) == 1 and redirects[0].severity == Severity.HIGH


def test_open_redirect_skipped_for_non_redirect_param_name():
    def responder(method, url, params):
        return FetchResult(ok=True, status_code=302, headers={"Location": "https://nxr-redirect.invalid/"}, text="")
    client = FakeClient(responder)
    findings = ap.probe_endpoint(client, ep({"q": "x"}), authenticated=False)
    assert not any("Open redirect" in f.title for f in findings)


def test_open_redirect_not_flagged_when_redirect_stays_internal():
    def responder(method, url, params):
        return FetchResult(ok=True, status_code=302, headers={"Location": "/home"}, text="")
    client = FakeClient(responder)
    findings = ap.probe_endpoint(client, ep({"next": "/home"}), authenticated=False)
    assert not any("Open redirect" in f.title for f in findings)


# --------------------------------------------------------------------- LFI

def test_lfi_etc_passwd_detected():
    def responder(method, url, params):
        if "etc/passwd" in params.get("file", "") or "etc%2fpasswd" in params.get("file", "").lower():
            return ok("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin")
        return ok("archivo no encontrado")
    client = FakeClient(responder)
    findings = ap.probe_endpoint(client, ep({"file": "doc.txt"}), authenticated=False)
    lfi = [f for f in findings if "LFI" in f.title]
    assert len(lfi) == 1 and lfi[0].severity == Severity.HIGH


def test_lfi_not_flagged_when_passwd_string_already_in_baseline():
    def responder(method, url, params):
        return ok("root:x:0:0:root:/root:/bin/bash")  # siempre presente, incluso sin payload
    client = FakeClient(responder)
    findings = ap.probe_endpoint(client, ep({"file": "doc.txt"}), authenticated=False)
    assert not any("LFI" in f.title for f in findings)


def test_lfi_windows_variant_detected():
    def responder(method, url, params):
        if "win.ini" in params.get("file", ""):
            return ok("[extensions]\nfor 16-bit app support")
        return ok("not found")
    client = FakeClient(responder)
    findings = ap.probe_endpoint(client, ep({"file": "doc.txt"}), authenticated=False)
    assert any("LFI" in f.title for f in findings)
