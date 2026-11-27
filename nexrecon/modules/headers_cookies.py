"""Análisis de cabeceras de seguridad y cookies. Misma lógica que en bash
(HSTS, XFO/frame-ancestors, CSP, X-Content-Type-Options, Referrer-Policy,
CORS, X-Powered-By/Server, flags de cookies), pero con cabeceras ya
parseadas a dict (sin greps) y cookies parseadas a objetos reales en vez
de evaluar substrings del Set-Cookie crudo cada vez.
"""
from __future__ import annotations

from ..http_client import HttpClient
from ..models import Cookie, HostResult, Severity


def _parse_cookie(raw: str) -> Cookie:
    """Parsea los atributos del Set-Cookie, no el texto crudo.

    Buscar "secure" como substring de toda la línea daba falsos
    positivos: una cookie llamada `secure_token=abc` (o con "secure" en
    su valor) contaba como si tuviera el flag Secure. El primer segmento
    antes del primer `;` es siempre `nombre=valor`; solo los siguientes
    son atributos.
    """
    segments = [seg.strip() for seg in raw.split(";")]
    name = segments[0].split("=", 1)[0].strip()
    attrs: dict[str, str] = {}
    for seg in segments[1:]:
        key, _, value = seg.partition("=")
        attrs[key.strip().lower()] = value.strip()

    same_site = {"lax": "Lax", "strict": "Strict", "none": "None"}.get(
        attrs.get("samesite", "").lower()
    )
    return Cookie(
        name=name,
        raw=raw,
        http_only="httponly" in attrs,
        secure="secure" in attrs,
        same_site=same_site,
    )


def analyze(client: HttpClient, host: HostResult, base_url: str) -> None:
    result = client.get(base_url)
    url_used = base_url

    if not result.ok:
        host.add_finding("No se pudo conectar para analizar cabeceras/cookies",
                          Severity.INFO, module="headers_cookies")
        return

    set_cookie = result.set_cookie_raw or []
    headers = {k.lower(): v for k, v in (result.headers or {}).items()}

    if not set_cookie:
        login_url = base_url.rstrip("/") + "/login"
        login_result = client.get(login_url)
        if login_result.ok and login_result.set_cookie_raw:
            set_cookie = login_result.set_cookie_raw
            headers = {k.lower(): v for k, v in (login_result.headers or {}).items()}
            url_used = login_url

    host.headers = headers

    # --- Cabeceras ---
    if "strict-transport-security" in headers:
        pass
    else:
        host.add_finding(
            "HSTS ausente", Severity.MEDIUM,
            "El sitio no fuerza HTTPS a nivel de navegador; permite downgrade "
            "a HTTP en la primera visita o en ataques de SSL stripping.",
            module="headers",
        )

    if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
        host.add_finding(
            "X-Frame-Options ausente", Severity.MEDIUM,
            "Sin X-Frame-Options ni frame-ancestors en CSP — posible clickjacking.",
            module="headers",
        )

    if "content-security-policy" not in headers:
        host.add_finding(
            "Content-Security-Policy ausente", Severity.MEDIUM,
            "Sin defensa en profundidad frente a XSS.", module="headers",
        )

    xcto = headers.get("x-content-type-options", "").lower()
    if "nosniff" not in xcto:
        host.add_finding(
            "X-Content-Type-Options ausente", Severity.LOW,
            "Permite MIME-sniffing.", module="headers",
        )

    if "referrer-policy" not in headers:
        host.add_finding(
            "Referrer-Policy ausente", Severity.LOW,
            "Puede filtrar URLs completas (con parámetros sensibles) a terceros vía Referer.",
            module="headers",
        )

    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "").lower()
    if acao and "*" in acao and acac == "true":
        host.add_finding(
            "CORS mal configurado", Severity.CRITICAL,
            "Access-Control-Allow-Origin: * junto con Allow-Credentials: true "
            "permite a cualquier origen leer respuestas autenticadas.",
            module="headers",
        )

    for hdr, label in (("x-powered-by", "X-Powered-By"), ("server", "Server")):
        if hdr in headers:
            host.add_finding(
                f"{label} expuesto: {headers[hdr]}", Severity.INFO,
                "Facilita fingerprinting de versión al atacante.", module="headers",
            )

    # --- Cookies ---
    for raw in set_cookie:
        cookie = _parse_cookie(client.auth.redact_set_cookie(raw) if client.auth else raw)
        host.cookies.append(cookie)

        if cookie.has_no_protection:
            host.add_finding(
                f"Cookie '{cookie.name}' sin ninguna flag de seguridad",
                Severity.CRITICAL,
                f"Vista en {url_used}. Máxima exposición: robable vía document.cookie "
                "en caso de XSS, enviable por HTTP plano, y sin protección CSRF.",
                module="cookies",
            )
            continue

        if not cookie.http_only:
            host.add_finding(
                f"Cookie '{cookie.name}' sin HttpOnly", Severity.HIGH,
                "Accesible vía document.cookie; robable en caso de XSS.", module="cookies",
            )
        if not cookie.secure:
            host.add_finding(
                f"Cookie '{cookie.name}' sin Secure", Severity.MEDIUM,
                "Puede transmitirse en texto plano si en algún momento se accede por HTTP.",
                module="cookies",
            )
        if cookie.same_site is None:
            host.add_finding(
                f"Cookie '{cookie.name}' sin SameSite", Severity.MEDIUM,
                "Expuesta a CSRF si no hay otras mitigaciones.", module="cookies",
            )
        elif cookie.same_site == "None" and not cookie.secure:
            host.add_finding(
                f"Cookie '{cookie.name}' con SameSite=None sin Secure", Severity.HIGH,
                "SameSite=None requiere Secure para ser válida en navegadores modernos.",
                module="cookies",
            )
