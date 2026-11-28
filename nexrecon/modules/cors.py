"""Comprobación activa de CORS mal configurado.

No intrusivo: una (o dos) peticiones GET con una cabecera `Origin`
distinta, sin payloads — por eso corre siempre en Fase 2, igual que
cabeceras/cookies, y no está gateado tras `--active-probes` (ese flag es
para payloads de ataque, no para esto).

`headers_cookies.analyze` ya detecta el caso más burdo y estático
(`Access-Control-Allow-Origin: *` + `Allow-Credentials: true` en la
respuesta normal, sin header Origin). Este módulo añade cobertura que
aquel no cubre: reflexión de un origen arbitrario (la app refleja
literalmente lo que se le manda en `Origin`, no un `*` fijo) y el caso
`Origin: null`. Ambos chequeos son complementarios, no duplicados.
"""
from __future__ import annotations

from ..http_client import HttpClient
from ..models import Confidence, Finding, HostResult, Severity

MODULE_NAME = "cors"
_REFERENCE = "https://portswigger.net/web-security/cors"
_ACAO = "access-control-allow-origin"
_ACAC = "access-control-allow-credentials"
_EVIL_ORIGIN = "https://nxr-evil.invalid"


def _cors_headers(headers: dict[str, str] | None) -> tuple[str, str]:
    lowered = {k.lower(): v for k, v in (headers or {}).items()}
    return lowered.get(_ACAO, ""), lowered.get(_ACAC, "").lower()


def check(client: HttpClient, host: HostResult, base_url: str) -> list[Finding]:
    findings: list[Finding] = []

    # Probe 1: ¿refleja un origen arbitrario (no solo "*" estático)?
    res = client.get(base_url, headers={"Origin": _EVIL_ORIGIN})
    if res.ok:
        acao, acac = _cors_headers(res.headers)
        if acao == _EVIL_ORIGIN and acac == "true":
            findings.append(Finding(
                title="CORS: origen arbitrario reflejado con credenciales",
                severity=Severity.CRITICAL, confidence=Confidence.CERTAIN, module=MODULE_NAME,
                reference=_REFERENCE,
                detail=f"Al mandar Origin: {_EVIL_ORIGIN}, la respuesta lo refleja tal cual "
                       f"en {_ACAO} junto con {_ACAC}: true — cualquier origen puede leer "
                       "respuestas autenticadas (robo de datos de sesión entre dominios). "
                       "Verificar manualmente con un origen propio antes de confirmar impacto.",
            ))
        elif acao == _EVIL_ORIGIN:
            findings.append(Finding(
                title="CORS: origen arbitrario reflejado (sin credenciales)",
                severity=Severity.MEDIUM, confidence=Confidence.FIRM, module=MODULE_NAME,
                reference=_REFERENCE,
                detail=f"La respuesta refleja el Origin enviado ({_EVIL_ORIGIN}) en {_ACAO}, "
                       "sin Allow-Credentials — impacto limitado a datos no sensibles "
                       "servidos sin autenticación, pero sigue siendo una mala práctica.",
            ))
        elif acao == "*":
            findings.append(Finding(
                title="CORS: Access-Control-Allow-Origin: * (sin credenciales)",
                severity=Severity.LOW, confidence=Confidence.CERTAIN, module=MODULE_NAME,
                reference=_REFERENCE,
                detail="Permisivo (cualquier origen puede leer la respuesta), pero sin "
                       "Allow-Credentials el impacto es limitado a contenido no autenticado.",
            ))

    # Probe 2: Origin: null (iframes sandboxed, redirecciones data:/file:, ...).
    res_null = client.get(base_url, headers={"Origin": "null"})
    if res_null.ok:
        acao_null, acac_null = _cors_headers(res_null.headers)
        if acao_null == "null":
            severity = Severity.HIGH if acac_null == "true" else Severity.MEDIUM
            findings.append(Finding(
                title="CORS: origen 'null' aceptado",
                severity=severity, confidence=Confidence.CERTAIN, module=MODULE_NAME,
                reference=_REFERENCE,
                detail="La respuesta acepta Origin: null"
                       + (" junto con Allow-Credentials: true" if acac_null == "true" else "")
                       + " — explotable desde un iframe sandboxed, una redirección "
                         "data:/file: o un documento sin origen. Verificar manualmente.",
            ))

    return findings
