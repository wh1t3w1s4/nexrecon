import json

from nexrecon.http_client import FetchResult
from nexrecon.models import HostResult
from nexrecon.modules import endpoint_discovery as ed

BASE = "https://t.example"

HTML = """
<html><body>
<form action="/search" method="get"><input name="q" value="x"><input type="submit" name="go"></form>
<form action="/login" method="POST">
  <input name="user"><input type="password" name="pw" value="hunter2">
  <input type="hidden" name="csrf" value="TOKENVALUE123"></form>
<form action="/logout"><button>salir</button></form>
<a href="/item?id=5&token=abc">i</a> <a href="https://other.com/x?a=1">ext</a> <a href="/plain">p</a>
<script src="/static/app.js"></script>
<script src="https://cdn.third.com/lib.js"></script>
</body></html>
"""


def test_parse_html_forms_links_scripts():
    eps, scripts = ed.parse_html(HTML, BASE + "/")
    by = {(e.method, e.url): e for e in eps}
    assert by[("GET", BASE + "/search")].params == {"q": "x"}
    login = by[("POST", BASE + "/login")]
    assert set(login.params) == {"user", "pw", "csrf"}
    assert login.hidden == ["pw", "csrf"]
    assert "hunter2" not in json.dumps([e.params for e in eps])      # password/hidden sin valor
    assert "TOKENVALUE123" not in json.dumps([e.params for e in eps])
    assert not any(e.url.endswith("/logout") for e in eps)            # formulario sin campos
    item = by[("GET", BASE + "/item")]
    assert item.params == {"id": "5", "token": ""}                    # token sin valor
    assert scripts == [BASE + "/static/app.js", "https://cdn.third.com/lib.js"]


def test_hidden_field_keeps_value_only_if_it_looks_like_a_url():
    # Caso real: stock-check de PortSwigger, un hidden con una URL (candidato
    # SSRF, no un secreto) frente a un hidden con un token (sí se borra).
    html = (
        '<form action="/stock" method="POST">'
        '<input type="hidden" name="stockApi" value="http://localhost/stock?productId=1">'
        '<input type="hidden" name="csrf" value="TOKEN123">'
        '<input type="submit"></form>'
    )
    eps, _ = ed.parse_html(html, BASE + "/")
    stock = next(e for e in eps if e.url.endswith("/stock"))
    assert stock.params["stockApi"] == "http://localhost/stock?productId=1"
    assert stock.params["csrf"] == ""
    assert set(stock.hidden) == {"stockApi", "csrf"}


JS = """
fetch("/api/users?page=1"); axios.post('/api/login', d); axios("/api/ping");
x.open("DELETE","/api/item/"+id); e.get("/api/orders/${id}/lines");
const r=[{path:"/dashboard"},{path:"/"}]; var s="/static/logo.png"; var t="https://cdn.third.com/api/x";
var u="https://t.example/api/abs"; var w="/api/a b"; var z="//t.example/api/proto-rel";
"""


def test_extract_js_endpoints():
    eps = ed.extract_js_endpoints(JS, BASE + "/app.js", BASE)
    got = {(e.method, e.url.replace(BASE, "")) for e in eps}
    assert ("GET", "/api/users") in got
    assert ("POST", "/api/login") in got
    assert ("GET", "/api/ping") in got
    assert ("DELETE", "/api/item/") in got
    assert ("GET", "/api/orders/{}/lines") in got
    assert ("GET", "/dashboard") in got
    assert ("GET", "/api/abs") in got and ("GET", "/api/proto-rel") in got
    flat = " ".join(e.url for e in eps)
    assert "logo.png" not in flat and "third.com" not in flat and "a b" not in flat
    assert not any(e.url == BASE + "/" for e in eps)
    assert next(e for e in eps if e.url.endswith("/api/users")).params == {"page": "1"}


class FakeClient:
    def __init__(self, routes):
        self.routes = routes
        self.requested = []

    def get(self, url, **_):
        self.requested.append(url)
        body = self.routes.get(url)
        if body is None:
            return FetchResult(ok=True, status_code=404, headers={}, text="", final_url=url)
        return FetchResult(ok=True, status_code=200, headers={"Content-Type": "text/html" if body.startswith("<") else "application/javascript"},
                           text=body, final_url=url)


def test_discover_same_host_js_only_and_sourcemap():
    smap = json.dumps({"version": 3, "sources": ["src/a.js", "node_modules/x.js"], "sourcesContent": ["a", "b"], "mappings": "AAAA"})
    client = FakeClient({
        BASE: HTML,
        BASE + "/static/app.js": "fetch('/api/me');\n//# sourceMappingURL=app.js.map",
        BASE + "/static/app.js.map": smap,
    })
    host = HostResult(hostname="t.example")
    findings = ed.discover(client, host, BASE)
    assert not any("third.com" in u for u in client.requested)        # nunca JS de terceros
    assert any(e.source == "js" and e.url.endswith("/api/me") for e in host.endpoints)
    assert len(findings) == 1 and findings[0].severity.value == "high"
    assert "sourcesContent" in findings[0].detail


def test_spa_fallback_is_not_a_sourcemap():
    client = FakeClient({
        BASE: HTML,
        BASE + "/static/app.js": "fetch('/api/me');",
        BASE + "/static/app.js.map": "<html>spa fallback</html>",
    })
    host = HostResult(hostname="t.example")
    assert ed.discover(client, host, BASE) == []


def test_endpoint_from_url_manual():
    ep = ed.endpoint_from_url("https://t.example/search?q=&secret_key=zz#frag")
    assert ep.url == "https://t.example/search" and ep.params == {"q": "", "secret_key": ""}
