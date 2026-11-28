"""Descubrimiento de endpoints: formularios HTML, enlaces con parámetros,
rutas de fuzzing y bundles JS (SPAs), unificados en una única lista de
`Endpoint` (`host.endpoints`) que consumen el reporte y `--active-probes`.

Solo lectura: unas pocas peticiones GET (tope fijo) y análisis de texto.
No envía payloads. Las peticiones salen por `HttpClient`, así que en modo
`--cookie` ven las páginas autenticadas.

Reglas del diseño:
- JS: solo `<script src>` del propio host. Nunca fonts, CDNs, analytics:
  ahí está casi todo el ruido.
- Los `.js.map` expuestos son hallazgo por sí solos (código fuente sin
  minificar). Se validan como JSON de source map real, porque muchas SPAs
  devuelven su index.html para cualquier ruta (falso positivo clásico).
- El primer filtro de rutas JS no será perfecto; las constantes de ruido
  están arriba para ajustarlas con práctica real.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse

from bs4 import BeautifulSoup

from ..http_client import HttpClient
from ..models import Confidence, Endpoint, Finding, HostResult, Severity

MODULE_NAME = "endpoint_discovery"

MAX_PAGES = 20
MAX_SCRIPTS = 15
MAX_ENDPOINTS = 300
MAX_JS_CHARS = 3_000_000

_STATIC_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".map", ".mp4", ".mp3",
    ".webm", ".pdf", ".zip", ".gz", ".js", ".mjs",
)
_SKIP_INPUT_TYPES = {"submit", "button", "image", "reset", "file"}
_HIDDEN_INPUT_TYPES = {"hidden", "password"}
# Valores de query que no deben persistirse en el reporte.
_SENSITIVE_PARAM = re.compile(r"token|key|secret|session|sess|auth|sig|pass|csrf|nonce", re.IGNORECASE)
# Excepción al borrado de valores hidden: una URL no es un secreto, y es
# justo el candidato SSRF típico (p. ej. `stockApi` en los labs de
# PortSwigger, un <input type="hidden"> con una URL interna como valor).
_LOOKS_LIKE_URL = re.compile(r"^(https?://|//)", re.IGNORECASE)

_JS_FETCH = re.compile(r"""\bfetch\(\s*[`'"]([^`'"]+)[`'"]""")
_JS_AXIOS = re.compile(r"""\baxios(?:\.(get|post|put|patch|delete|head|options))?\(\s*[`'"]([^`'"]+)[`'"]""")
_JS_XHR = re.compile(r"""\.open\(\s*[`'"](GET|POST|PUT|PATCH|DELETE)[`'"]\s*,\s*[`'"]([^`'"]+)[`'"]""")
# En código minificado la instancia suele llamarse `e`/`t`: no se puede
# depender de `axios.`, así que también se recogen strings con forma de API.
_JS_API_STRING = re.compile(
    r"""[`'"]((?:https?:)?//[^`'"\s]+|/(?:api|rest|graphql|v\d+|auth|oauth|admin|user|users|account|login|logout)\b[^`'"\s]*)[`'"]"""
)
_JS_ROUTE = re.compile(r"""\bpath\s*:\s*[`'"](/[^`'"\s]*)[`'"]""")
_JS_TEMPLATE_EXPR = re.compile(r"\$\{[^}]*\}")
_SOURCEMAP_COMMENT = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)\s*$", re.MULTILINE)


# ------------------------------------------------------------- secretos JS

@dataclass(frozen=True)
class SecretPattern:
    name: str
    regex: re.Pattern
    severity: Severity
    confidence: Confidence
    note: str = ""   # p. ej. "las API keys de Google Maps suelen ser públicas por diseño"


_SECRET_PATTERNS: list[SecretPattern] = [
    SecretPattern("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
                  Severity.HIGH, Confidence.FIRM),
    SecretPattern("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
                  Severity.LOW, Confidence.FIRM,
                  "Puede ser una clave pública de cliente (Maps/JS) — verificar restricciones."),
    SecretPattern("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
                  Severity.HIGH, Confidence.CERTAIN),
    SecretPattern("Stripe Live Secret Key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{24,}\b"),
                  Severity.CRITICAL, Confidence.CERTAIN),
    SecretPattern("GitHub Token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{36,}\b"),
                  Severity.HIGH, Confidence.CERTAIN),
    SecretPattern("Private Key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
                  Severity.CRITICAL, Confidence.CERTAIN),
    SecretPattern("Twilio Account SID", re.compile(r"\bAC[0-9a-fA-F]{32}\b"),
                  Severity.MEDIUM, Confidence.FIRM),
    SecretPattern("Mailgun/Generic key", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"),
                  Severity.MEDIUM, Confidence.FIRM),
    SecretPattern("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
                  Severity.MEDIUM, Confidence.TENTATIVE, "Puede ser un token de ejemplo/expirado."),
    # genérico, siempre TENTATIVE y filtrado por entropía (ver `_is_plausible_secret`):
    SecretPattern(
        "Posible credencial genérica",
        re.compile(
            r"""(?i)(?:api[_-]?key|secret|token|passwd|password|access[_-]?key)\s*[:=]\s*['"]([^'"\s]{12,})['"]"""
        ),
        Severity.MEDIUM, Confidence.TENTATIVE,
    ),
]

_PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:x{3,}|your|example|test|dummy|changeme|placeholder|<[^>]+>|\$\{|\{\{|null|undefined)"
)
_MIN_GENERIC_ENTROPY = 3.2  # bits/char; texto natural ronda 2.5-3, secretos aleatorios 4+
MAX_SECRET_FINDINGS = 25


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _is_plausible_secret(value: str) -> bool:
    if _PLACEHOLDER_RE.match(value):
        return False
    return _shannon_entropy(value) >= _MIN_GENERIC_ENTROPY


def _mask(value: str) -> str:
    if len(value) <= 8:
        return value
    return f"{value[:4]}…{value[-2:]} ({len(value)} car.)"


def scan_js_secrets(js: str, script_url: str, seen: set[str]) -> list[Finding]:
    """Escanea un bundle JS ya descargado en busca de credenciales filtradas.

    Coste marginal casi nulo: `js` ya está en memoria (se descargó para
    `extract_js_endpoints`/`check_source_map`), esto es solo más regex sobre
    el mismo texto. `seen` deduplica el mismo valor visto en otro script del
    mismo host (p. ej. una clave repetida en varios bundles).
    """
    findings: list[Finding] = []
    for pattern in _SECRET_PATTERNS:
        for match in pattern.regex.finditer(js):
            if len(findings) + len(seen) >= MAX_SECRET_FINDINGS:
                return findings
            # Los patrones con grupo de captura son el genérico (clave=valor);
            # el resto matchea el secreto completo (no tienen grupos).
            value = match.group(1) if match.groups() else match.group(0)
            if pattern.confidence is Confidence.TENTATIVE and not _is_plausible_secret(value):
                continue
            if value in seen:
                continue
            seen.add(value)
            detail = f"Valor: {_mask(value)}, encontrado en {script_url}."
            if pattern.note:
                detail += f" {pattern.note}"
            findings.append(Finding(
                title=f"Posible secreto filtrado en JS: {pattern.name}",
                severity=pattern.severity, detail=detail, module=MODULE_NAME,
                confidence=pattern.confidence,
            ))
    return findings


# --------------------------------------------------------------- utilidades

def _netloc(url: str) -> str:
    return urlparse(url).netloc.lower()


def _same_host(url: str, base_url: str) -> bool:
    return _netloc(url) == _netloc(base_url)


def _is_static(path: str) -> bool:
    return path.lower().split("?", 1)[0].endswith(_STATIC_EXT)


def _is_html(result) -> bool:
    ctype = {k.lower(): v for k, v in (result.headers or {}).items()}.get("content-type", "")
    return "html" in ctype.lower() or result.text.lstrip()[:15].lower().startswith(("<!doctype", "<html"))


def _clean_value(name: str, value: str) -> str:
    return "" if _SENSITIVE_PARAM.search(name) else value


def endpoint_from_url(url: str, method: str = "GET", source: str = "manual",
                      found_in: str = "") -> Endpoint:
    """URL (con o sin query) -> Endpoint. Sirve también para `--param`:
    `https://t.com/search?q=` -> params {"q": ""}."""
    url, _ = urldefrag(url)
    parsed = urlparse(url)
    params = {k: _clean_value(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)}
    return Endpoint(
        url=parsed._replace(query="", fragment="").geturl(),
        method=method.upper(), params=params, source=source, found_in=found_in,
    )


# ------------------------------------------------------------------ HTML

def parse_html(html: str, page_url: str) -> tuple[list[Endpoint], list[str]]:
    """Devuelve (endpoints de formularios y enlaces con query, URLs de <script src>)."""
    soup = BeautifulSoup(html, "html.parser")
    endpoints: list[Endpoint] = []

    for form in soup.find_all("form"):
        method = (form.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            method = "GET"
        action = urljoin(page_url, form.get("action") or page_url)
        params: dict[str, str] = {}
        hidden: list[str] = []
        for el in form.find_all(["input", "select", "textarea"]):
            name = el.get("name")
            if not name:
                continue
            kind = (el.get("type") or "text").lower() if el.name == "input" else el.name
            if kind in _SKIP_INPUT_TYPES:
                continue
            if kind in _HIDDEN_INPUT_TYPES:
                hidden.append(name)
                raw_value = el.get("value") or ""
                # password: siempre vacío. hidden: vacío salvo que la forma
                # del valor sea una URL (ahí no hay nada que proteger y sí
                # algo que detectar).
                params[name] = raw_value if kind == "hidden" and _LOOKS_LIKE_URL.match(raw_value) else ""
            else:
                params[name] = _clean_value(name, el.get("value") or "") if el.name == "input" else ""
        if params:
            ep = endpoint_from_url(action, method=method, source="form", found_in=page_url)
            ep.params = {**ep.params, **params}
            ep.hidden = hidden
            endpoints.append(ep)

    for a in soup.find_all("a", href=True):
        href = urljoin(page_url, a["href"])
        if urlparse(href).scheme in ("http", "https") and "?" in href:
            endpoints.append(endpoint_from_url(href, source="link", found_in=page_url))

    scripts = [urljoin(page_url, s["src"]) for s in soup.find_all("script", src=True)]
    return endpoints, scripts


# -------------------------------------------------------------------- JS

def _clean_js_path(raw: str, base_url: str) -> str | None:
    """Normaliza una cadena encontrada en JS a URL absoluta del propio host,
    o None si parece ruido (asset estático, regex, HTML, otro host...)."""
    raw = _JS_TEMPLATE_EXPR.sub("{}", raw.strip())
    if not raw or len(raw) > 200 or re.search(r"[\s<>()\\^$*|]", raw):
        return None
    if raw.startswith("//"):
        raw = f"{urlparse(base_url).scheme}:{raw}"
    if raw.startswith(("http://", "https://")):
        if not _same_host(raw, base_url):
            return None  # nunca endpoints de terceros
    elif not raw.startswith("/"):
        return None
    url = urljoin(base_url, raw)
    path = urlparse(url).path
    if path in ("", "/") or _is_static(path):
        return None
    return url


def extract_js_endpoints(js: str, script_url: str, base_url: str) -> list[Endpoint]:
    found: list[tuple[str, str]] = []  # (método, url)
    for m in _JS_FETCH.finditer(js):
        found.append(("GET", m.group(1)))
    for m in _JS_AXIOS.finditer(js):
        found.append(((m.group(1) or "GET").upper(), m.group(2)))
    for m in _JS_XHR.finditer(js):
        found.append((m.group(1).upper(), m.group(2)))
    for m in _JS_API_STRING.finditer(js):
        found.append(("GET", m.group(1)))
    for m in _JS_ROUTE.finditer(js):
        found.append(("GET", m.group(1)))

    endpoints = []
    for method, raw in found:
        url = _clean_js_path(raw, base_url)
        if url:
            endpoints.append(endpoint_from_url(url, method=method, source="js", found_in=script_url))
    return endpoints


def check_source_map(client: HttpClient, script_url: str, js: str, base_url: str) -> Finding | None:
    comment = _SOURCEMAP_COMMENT.search(js[-1000:])
    ref = comment.group(1) if comment else None
    if ref and ref.startswith("data:"):
        return None  # inline en el propio bundle: no es un fichero expuesto aparte
    map_url = urljoin(script_url, ref) if ref else script_url + ".map"
    if not _same_host(map_url, base_url):
        return None

    res = client.get(map_url)
    if not res.ok or res.status_code != 200:
        return None
    try:
        data = json.loads(res.text)
    except ValueError:
        return None  # p. ej. el index.html de una SPA servido para cualquier ruta
    if not isinstance(data, dict) or not ("mappings" in data or "sources" in data):
        return None

    sources = [s for s in data.get("sources", []) if isinstance(s, str)]
    has_content = bool(data.get("sourcesContent"))
    app_sources = [s for s in sources if "node_modules" not in s]
    detail = (
        f"{map_url} — {len(sources)} fichero(s) fuente referenciados "
        f"({len(app_sources)} fuera de node_modules)"
        + ("; incluye `sourcesContent`: código fuente original completo recuperable" if has_content else "")
        + ". Revisar manualmente rutas de API, claves y lógica de negocio expuestas."
    )
    return Finding(
        title=f"Source map expuesto: {urlparse(map_url).path}",
        severity=Severity.HIGH, detail=detail, module=MODULE_NAME,
    )


# ----------------------------------------------------------- orquestación

def _candidate_pages(host: HostResult, base_url: str) -> list[str]:
    pages = [base_url]
    for hit in host.directories_clean:
        if hit.status == 200 and _same_host(hit.url, base_url) and not _is_static(urlparse(hit.url).path):
            pages.append(hit.url)
    return list(dict.fromkeys(pages))[:MAX_PAGES]


def discover(client: HttpClient, host: HostResult, base_url: str) -> list[Finding]:
    """Rellena `host.endpoints` y devuelve hallazgos (source maps, secretos en JS)."""
    findings: list[Finding] = []
    seen: dict[tuple, Endpoint] = {}
    seen_secrets: set[str] = set()  # dedup de valores repetidos entre scripts de este host

    def add(ep: Endpoint) -> None:
        if len(seen) < MAX_ENDPOINTS:
            seen.setdefault(ep.key, ep)

    scripts: list[str] = []
    for page in _candidate_pages(host, base_url):
        res = client.get(page)
        if not res.ok or res.status_code != 200 or not _is_html(res):
            continue
        eps, page_scripts = parse_html(res.text, res.final_url or page)
        for ep in eps:
            if _same_host(ep.url, base_url):
                add(ep)
        scripts += [s for s in page_scripts if _same_host(s, base_url)]  # solo JS propio
        if page == base_url:
            # Secretos en <script> inline de la página raíz — barato, ya se
            # descargó el HTML para parsear formularios/enlaces.
            findings += scan_js_secrets(res.text, f"HTML inline de {page}", seen_secrets)

    for script_url in list(dict.fromkeys(scripts))[:MAX_SCRIPTS]:
        res = client.get(script_url)
        if not res.ok or res.status_code != 200:
            continue
        js = res.text[:MAX_JS_CHARS]
        for ep in extract_js_endpoints(js, script_url, base_url):
            add(ep)
        finding = check_source_map(client, script_url, js, base_url)
        if finding:
            findings.append(finding)
        findings += scan_js_secrets(js, script_url, seen_secrets)

    host.endpoints = sorted(seen.values(), key=lambda e: (e.source, e.url, e.method))
    return findings
