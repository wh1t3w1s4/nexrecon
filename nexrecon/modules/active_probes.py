"""Sondas activas de detección (`--active-probes`).

Eje de intrusividad, independiente de `--deep` ("cuánto miro" vs "qué tan
intrusivo soy"): nunca se activa por defecto, ni siquiera bajo `--deep`.

SOLO detección, nunca explotación: un único payload no destructivo por
técnica, comparado contra una petición base sin payload para reducir
falsos positivos. Ningún hallazgo de este módulo se marca como
"explotado" — el texto de cada `Finding` deja la verificación/explotación
como tarea manual del usuario, tal como se pidió explícitamente.

Objetivos: `host.endpoints` (de `endpoint_discovery`) o, en modo manual,
un único `Endpoint` construido desde `--param "https://target.com/search?q="`.

Cada hallazgo lleva también `confidence` (ver `models.Confidence`), un eje
independiente de la severidad: cuánto nos fiamos de la señal, no cuánto
importaría si fuera real.

Técnicas, severidad y confianza acordadas:
  - SSTI    ({{7*7}} -> 49, confirmado con una segunda expresión,          CRITICAL / CERTAIN
            varios motores de plantillas — ver `_SSTI_STYLES`)
  - SQLi    (comilla simple + error de BD visible o 500 nuevo)             HIGH / FIRM
  - XSS     (marcador único reflejado sin escapar, varias variantes)       HIGH / FIRM
  - IDOR    (ID vecino con respuesta distinta y sin señal de error)        MEDIUM/HIGH, TENTATIVE/FIRM
            (HIGH+FIRM si la sesión venía de --cookie: ahí sí hay control de
            acceso real que comprobar, no solo una respuesta curiosa sin sesión)
  - Open redirect (canario externo en parámetros con forma de redirect,   MEDIUM/HIGH, CERTAIN
            sin seguir la redirección; HIGH si el parámetro es OAuth-like)
  - LFI/path traversal (firma de /etc/passwd o windows/win.ini ausente     HIGH / CERTAIN
            en la respuesta base)
  - SSRF    (solo nombre/valor de parámetro con forma de URL, SIN payload  INFO/LOW, TENTATIVE
            activo salvo que el propio usuario use un receptor OOB a mano)

Primer filtro, pensado para iterar con uso real en labs (pentest-tools,
PortSwigger): heurísticas simples, no un motor de reglas completo.
"""
from __future__ import annotations

import argparse
import re
import sys
import uuid
from urllib.parse import urlparse

from ..http_client import FetchResult, HttpClient
from ..models import Confidence, Endpoint, Finding, HostResult, Severity
from .endpoint_discovery import endpoint_from_url

MODULE_NAME = "active_probes"

# Topes duros: un sitio real puede tener cientos de endpoints/parámetros,
# y cada uno aquí cuesta varias peticiones (SQLi+XSS+SSTI+IDOR por parámetro).
MAX_ENDPOINTS = 40
MAX_PARAMS_PER_ENDPOINT = 6
PROBE_TIMEOUT = 12

_SQL_ERROR_PATTERNS = re.compile(
    r"sql syntax|mysql_fetch|you have an error in your sql|unclosed quotation mark|"
    r"quoted string not properly terminated|pg_query\(|sqlite3\.OperationalError|"
    r"ORA-\d{5}|odbc (?:driver|microsoft access)|warning: mysqli?|"
    r"syntax error at or near|sqlstate\[|System\.Data\.SqlClient",
    re.IGNORECASE,
)
_DENY_PATTERNS = re.compile(
    r"access denied|forbidden|not authorized|unauthoriz|no permission|"
    r"acceso denegado|no autorizado|no tienes permiso",
    re.IGNORECASE,
)
_ID_PARAM_NAME = re.compile(r"(^|_)id$", re.IGNORECASE)
_SSRF_PARAM_NAME = re.compile(
    r"url|uri|link|redirect|return|callback|webhook|src|target|dest|path|"
    r"load|fetch|proxy|next|continue|image|avatar|site|host",
    re.IGNORECASE,
)
_SSRF_VALUE_RE = re.compile(r"^(https?://|//|[\w.-]+\.[a-z]{2,}(/|$))", re.IGNORECASE)
# `?`, `=` y `&` no son especiales para bash/zsh dentro de comillas — no
# necesitan escaparse, y un "\?"/"\=" copiado de otro sitio suele colarse
# como backslash LITERAL en la URL, rompiéndola en silencio.
_SUSPICIOUS_SHELL_ESCAPE_RE = re.compile(r"\\[?=&]")


def argparse_param(raw: str) -> Endpoint:
    """`type=` para argparse: construye el Endpoint manual de `--param`.

    Tiene que ser una URL ABSOLUTA (con esquema y host). Una ruta relativa
    como '/filter?category=' parsea sin error pero luego ninguna petición
    puede salir con ella — y antes eso se traducía en un silencioso "sin
    hallazgos" sin pista de qué había fallado.
    """
    if _SUSPICIOUS_SHELL_ESCAPE_RE.search(raw):
        print(
            "\033[33m"  # amarillo, para que destaque sin depender de rich (este módulo no lo usa)
            f"[nexrecon] aviso: '{raw}' contiene '\\?', '\\=' o '\\&'. En bash/zsh, dentro "
            "de comillas esos caracteres NO necesitan escaparse — ese backslash puede "
            "colarse literal en la URL y romperla en silencio. Si el resultado no es el "
            "esperado, prueba sin backslashes: --param 'https://target.com/search?q='"
            "\033[0m",
            file=sys.stderr,
        )
    parsed = urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise argparse.ArgumentTypeError(
            f"'{raw}' no es una URL completa — falta el esquema y/o el host "
            "(usa 'https://target.com/search?q=', no solo '/search?q=' o 'search?q=')"
        )
    ep = endpoint_from_url(raw, source="manual")
    if not ep.params:
        raise argparse.ArgumentTypeError(
            f"'{raw}' no tiene ningún parámetro de query (se esperaba algo como "
            "'https://target.com/search?q=')"
        )
    return ep


def _finding(title: str, severity: Severity, ep: Endpoint, param: str, detail: str,
            confidence: Confidence = Confidence.FIRM) -> Finding:
    return Finding(
        title=title, severity=severity,
        detail=f"{ep.method} {ep.url} (parámetro: {param}, origen: {ep.source}). {detail}",
        module=MODULE_NAME, confidence=confidence,
    )


def _send(client: HttpClient, ep: Endpoint, params: dict[str, str]) -> FetchResult | None:
    if ep.method == "POST":
        res = client.post(ep.url, data=params, timeout=PROBE_TIMEOUT)
    else:
        res = client.request("GET", ep.url, params=params, timeout=PROBE_TIMEOUT)
    return res if res.ok else None


# --------------------------------------------------------------- técnicas

def _probe_sqli(client: HttpClient, ep: Endpoint, name: str, value: str,
                baseline: FetchResult) -> list[Finding]:
    res = _send(client, ep, {**ep.params, name: value + "'"})
    if not res:
        return []
    new_error = _SQL_ERROR_PATTERNS.search(res.text) and not _SQL_ERROR_PATTERNS.search(baseline.text)
    new_500 = res.status_code == 500 and baseline.status_code != 500
    if not (new_error or new_500):
        return []
    return [_finding(
        f"Posible SQLi en parámetro '{name}'", Severity.HIGH, ep, name,
        "Añadir una comilla simple al valor original provocó un error de base de "
        "datos (o un 500) que no aparece con el valor sin modificar. Verificar "
        "manualmente, p. ej. con sqlmap; no se ha intentado extraer ni explotar nada.",
    )]


def _probe_xss(client: HttpClient, ep: Endpoint, name: str, value: str,
               _baseline: FetchResult) -> list[Finding]:
    """Varias variantes de marcador, no solo una: una app puede escapar
    comillas pero no ángulos (o al revés), y una sola variante compuesta
    se pierde esos casos aunque el parámetro sea igualmente vulnerable.
    Se prueba cada una por separado y basta con que UNA se refleje intacta.
    """
    tag = uuid.uuid4().hex[:10]
    variants = (
        f'<nxr{tag}a>',          # ruptura de contexto HTML (texto plano)
        f'"><nxr{tag}b>',        # ruptura de atributo con comillas dobles
        f"'><nxr{tag}c>",        # ruptura de atributo con comillas simples
    )
    for marker in variants:
        res = _send(client, ep, {**ep.params, name: value + marker})
        if res and marker in res.text:
            return [_finding(
                f"Posible XSS reflejado en parámetro '{name}'", Severity.HIGH, ep, name,
                f"El marcador único {marker!r} se reflejó TAL CUAL en la respuesta (sin "
                "codificar), sin que la página lo escape. Verificar manualmente si cae en "
                "un contexto ejecutable; no se ha intentado disparar ningún script.",
            )]
    return []


# Varios motores de plantillas, cada uno con su propia sintaxis — se
# prueban todos porque no hay forma de saber de antemano cuál usa el
# target. Cada estilo exige su propia doble confirmación (7*7->49 y
# 8*8->64) para no depender de una coincidencia.
# Jinja2/Twig primero porque es el más común y es el que ya venía
# funcionando — no se quita, solo se añaden más estilos detrás.
_SSTI_STYLES = (
    ("{{7*7}}", "{{8*8}}"),        # Jinja2 / Twig
    ("${7*7}", "${8*8}"),          # Freemarker
    ("<%= 7*7 %>", "<%= 8*8 %>"),  # ERB (Ruby/Rails)
    ("{7*7}", "{8*8}"),            # Smarty
)


def _probe_ssti(client: HttpClient, ep: Endpoint, name: str, value: str,
                baseline: FetchResult) -> list[Finding]:
    def hit(expr: str, product: str) -> bool:
        res = _send(client, ep, {**ep.params, name: value + expr})
        return bool(
            res and expr not in res.text and product in res.text and product not in baseline.text
        )

    for expr_a, expr_b in _SSTI_STYLES:
        if hit(expr_a, "49") and hit(expr_b, "64"):
            return [_finding(
                f"Posible SSTI en parámetro '{name}'", Severity.CRITICAL, ep, name,
                f"{expr_a} se evaluó a 49 y {expr_b} a 64 en la respuesta (ambos ausentes "
                "con el valor original) — el motor de plantillas está ejecutando la "
                "entrada del usuario. Suele escalar a RCE casi de inmediato: verificar "
                "manualmente con cuidado, en un entorno autorizado; no se ha intentado "
                "ejecutar código. Nota: si el campo ya está dentro de una expresión de "
                "plantilla abierta por la propia app (p. ej. necesitas cerrarla con '}}' "
                "antes de la tuya), esta sonda no lo detecta — es un caso específico del "
                "lab/app, no genérico.",
                confidence=Confidence.CERTAIN,
            )]
    return []


def _probe_idor(client: HttpClient, ep: Endpoint, baseline: FetchResult,
                authenticated: bool) -> list[Finding]:
    findings = []
    for name, value in ep.params.items():
        if name in ep.hidden or not value.isdigit() or not _ID_PARAM_NAME.search(name):
            continue
        neighbor = str(int(value) + 1)
        res = _send(client, ep, {**ep.params, name: neighbor})
        if (not res or res.status_code != 200 or baseline.status_code != 200
                or res.text == baseline.text or _DENY_PATTERNS.search(res.text)):
            continue
        severity = Severity.HIGH if authenticated else Severity.MEDIUM
        confidence = Confidence.FIRM if authenticated else Confidence.TENTATIVE
        findings.append(_finding(
            f"Posible IDOR en parámetro '{name}'", severity, ep, name,
            f"Cambiar {name}={value} por {name}={neighbor} devolvió 200 con un cuerpo "
            "distinto al original y sin señales de error/acceso denegado — podría ser "
            "un registro de otro usuario. Verificar manualmente el contenido devuelto; "
            "no se ha extraído ni guardado nada de esa respuesta."
            + (" Sesión autenticada (--cookie): si el objeto pertenece a otra cuenta, "
               "es un control de acceso roto confirmable de inmediato." if authenticated else
               " Sin sesión activa: confirma primero si el recurso debería requerir login."),
            confidence=confidence,
        ))
    return findings


def _probe_ssrf_candidates(ep: Endpoint) -> list[Finding]:
    """Solo detección estática por nombre/forma del parámetro — SIN enviar
    ningún payload activo, tal como se decidió (salvo que el usuario quiera
    usar un receptor OOB propio para confirmar manualmente).
    """
    findings = []
    for name, value in ep.params.items():
        # A diferencia de SQLi/XSS/SSTI/IDOR, esto no manda ninguna petición,
        # así que SÍ se revisan los campos hidden: el candidato SSRF típico
        # (p. ej. `stockApi` en los labs de PortSwigger) suele venir oculto.
        value_looks_url = bool(value) and bool(_SSRF_VALUE_RE.match(value))
        if not (value_looks_url or _SSRF_PARAM_NAME.search(name)):
            continue
        severity = Severity.LOW if value_looks_url else Severity.INFO
        findings.append(_finding(
            f"Parámetro candidato a SSRF: '{name}'", severity, ep, name,
            "El nombre y/o el valor del parámetro sugieren que el servidor podría "
            "hacer una petición a la URL indicada. No se ha enviado ningún payload "
            "activo (solo detección estática del candidato). Para confirmar, usa "
            "manualmente un receptor OOB propio (p. ej. requestrepo.com o interactsh) "
            "— esta herramienta no lo hace por ti.",
            confidence=Confidence.TENTATIVE,
        ))
    return findings


# ------------------------------------------------------- open redirect

_REDIRECT_PARAM = re.compile(
    r"(?i)^(?:url|uri|redirect|redirect_uri|return|returnurl|returnto|"
    r"goto|next|dest|destination|continue|r|u|target|callback)$"
)
# .invalid es el TLD reservado para esto (RFC 2606): nunca resuelve, nunca
# se visita de verdad — el canario es inerte incluso si algo lo siguiera.
_REDIRECT_CANARY = "nxr-redirect.invalid"
_OAUTH_LIKE_PARAMS = {"redirect_uri", "returnurl", "callback"}


def _send_no_redirect(client: HttpClient, ep: Endpoint, params: dict[str, str]) -> FetchResult | None:
    if ep.method == "POST":
        res = client.post(ep.url, data=params, allow_redirects=False, timeout=PROBE_TIMEOUT)
    else:
        res = client.request("GET", ep.url, params=params, allow_redirects=False, timeout=PROBE_TIMEOUT)
    return res if res.ok else None


def _probe_open_redirect(client: HttpClient, ep: Endpoint, name: str, value: str,
                         _baseline: FetchResult) -> list[Finding]:
    if not _REDIRECT_PARAM.match(name):
        return []
    for payload in (f"https://{_REDIRECT_CANARY}/", f"//{_REDIRECT_CANARY}/"):
        res = _send_no_redirect(client, ep, {**ep.params, name: payload})
        if not res:
            continue
        location = {k.lower(): v for k, v in (res.headers or {}).items()}.get("location", "")
        if 300 <= res.status_code < 400 and _REDIRECT_CANARY in urlparse(location).netloc:
            severity = Severity.HIGH if name.lower() in _OAUTH_LIKE_PARAMS else Severity.MEDIUM
            return [_finding(
                f"Open redirect en parámetro '{name}'", severity, ep, name,
                f"Con el valor '{payload}', la respuesta ({res.status_code}) trae "
                f"Location: {location!r}, apuntando al canario externo. No se siguió la "
                "redirección; verificar manualmente el impacto (phishing, robo de token "
                "en flujos OAuth si el parámetro es de ese tipo).",
                confidence=Confidence.CERTAIN,
            )]
    return []


# --------------------------------------------------------- LFI / traversal

_LFI_PASSWD_RE = re.compile(r"root:.*?:0:0:", re.MULTILINE)
_LFI_WININI_RE = re.compile(r"\[extensions\]|for 16-bit app support", re.IGNORECASE)
_LFI_PAYLOADS = (
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",                 # bypass de filtro simple de "../"
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",    # URL-encoded
    "../../../../../../windows/win.ini",
)
# Deliberadamente SIN payloads de null-byte (%00): técnica obsoleta en
# intérpretes modernos y solo añade ruido.


def _probe_lfi(client: HttpClient, ep: Endpoint, name: str, value: str,
               baseline: FetchResult) -> list[Finding]:
    for payload in _LFI_PAYLOADS:
        res = _send(client, ep, {**ep.params, name: payload})
        if not res:
            continue
        got_passwd = bool(_LFI_PASSWD_RE.search(res.text)) and not _LFI_PASSWD_RE.search(baseline.text)
        got_wini = bool(_LFI_WININI_RE.search(res.text)) and not _LFI_WININI_RE.search(baseline.text)
        if got_passwd or got_wini:
            target = "/etc/passwd" if got_passwd else "windows/win.ini"
            return [_finding(
                f"Posible LFI/Path Traversal en parámetro '{name}'", Severity.HIGH, ep, name,
                f"El payload '{payload}' devolvió contenido de {target} ausente en la "
                "respuesta base. Verificar manualmente; no se ha extraído ningún fichero "
                "más allá de confirmar la firma en la respuesta.",
                confidence=Confidence.CERTAIN,
            )]
    return []


# ----------------------------------------------------------------- runner

def probe_endpoint(client: HttpClient, ep: Endpoint, authenticated: bool) -> list[Finding]:
    testable = [(n, v) for n, v in ep.params.items() if n not in ep.hidden]
    findings = _probe_ssrf_candidates(ep)  # no necesita baseline ni red
    if not testable:
        return findings

    baseline = _send(client, ep, ep.params)
    if baseline is None:
        # Antes esto se traducía en un "sin hallazgos" indistinguible de
        # "se probó y no había nada" — aquí ni siquiera se pudo probar.
        findings.append(_finding(
            "No se pudo probar este endpoint", Severity.INFO, ep,
            ", ".join(n for n, _ in testable),
            "La petición de referencia (sin payload) falló — revisa que la URL "
            "incluya esquema y host, que sea alcanzable, y que el método/parámetros "
            "sean correctos. No se puede descartar una vulnerabilidad sin haber "
            "podido probarla.",
        ))
        return findings

    for name, value in testable[:MAX_PARAMS_PER_ENDPOINT]:
        findings += _probe_sqli(client, ep, name, value, baseline)
        findings += _probe_xss(client, ep, name, value, baseline)
        findings += _probe_ssti(client, ep, name, value, baseline)
        findings += _probe_open_redirect(client, ep, name, value, baseline)
        findings += _probe_lfi(client, ep, name, value, baseline)
    findings += _probe_idor(client, ep, baseline, authenticated)
    return findings


def run(client: HttpClient, host: HostResult, manual: Endpoint | None = None) -> list[Finding]:
    """Punto de entrada. Sin `manual`, prueba `host.endpoints` con al menos
    un parámetro (hasta `MAX_ENDPOINTS`); con `manual` (de `--param`), es el
    ÚNICO objetivo — así se apunta a un campo concreto.
    """
    targets = [manual] if manual else [e for e in host.endpoints if e.params][:MAX_ENDPOINTS]

    authenticated = client.auth is not None
    findings: list[Finding] = []
    for ep in targets:
        findings += probe_endpoint(client, ep, authenticated)
    return findings
