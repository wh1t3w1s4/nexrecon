"""Verificación activa de subdomain takeover.

`config.CNAME_PATTERNS` (usado por `dns_recon`) ya ANOTA un CNAME como
"posible takeover si el recurso no existe" — pero no lo comprueba. Este
módulo cierra ese bucle: resuelve el CNAME, y si el destino está colgando
(NXDOMAIN) o el cuerpo HTTP trae la huella de "recurso no reclamado" de un
proveedor conocido (`config.TAKEOVER_SIGNATURES`, basada en
can-i-take-over-xyz), lo reporta como CERTAIN — ya no es una anotación
pasiva, es una confirmación.

Solo CNAME (v1): los takeovers por registro A (IPs de rangos de nube
liberadas/reasignables) quedan fuera de alcance por ahora.
"""
from __future__ import annotations

from .. import config
from ..http_client import HttpClient
from ..models import Confidence, Finding, Severity
from . import dns_recon

MODULE_NAME = "takeover"
_REFERENCE = "https://github.com/EdOverflow/can-i-take-over-xyz"


def _matching_signature(cname: str) -> config.TakeoverSignature | None:
    for sig in config.TAKEOVER_SIGNATURES:
        if any(marker in cname for marker in sig.cname_contains):
            return sig
    return None


def check_host(client: HttpClient, hostname: str) -> Finding | None:
    cname = dns_recon.resolve_cname(hostname)
    if not cname:
        return None  # sin CNAME: esta clase de takeover no aplica

    sig = _matching_signature(cname)
    if not sig:
        return None  # CNAME a un servicio que no reconocemos

    if not dns_recon.resolves(cname):
        return Finding(
            title=f"Posible subdomain takeover: {hostname} -> {sig.service}",
            severity=Severity.HIGH, confidence=Confidence.CERTAIN, module=MODULE_NAME,
            reference=_REFERENCE,
            detail=f"CNAME hacia {cname} ({sig.service}) no resuelve (NXDOMAIN) — el "
                   "recurso de destino ya no existe, el subdominio sigue apuntando a él. "
                   "Verificar manualmente si el nombre/bucket/app puede reclamarse de "
                   "nuevo en ese proveedor antes de dar por confirmada la explotación.",
        )

    for scheme in ("https", "http"):
        res = client.get(f"{scheme}://{hostname}", allow_redirects=True)
        if not res.ok:
            continue
        hit = next((fp for fp in sig.body_fingerprints if fp in res.text), None)
        if hit:
            confidence = Confidence.CERTAIN if sig.vulnerable else Confidence.FIRM
            caveat = "" if sig.vulnerable else (
                " Nota: este proveedor ya no suele permitir reclamar el recurso "
                "directamente — puede requerir pasos adicionales o no ser explotable."
            )
            return Finding(
                title=f"Posible subdomain takeover: {hostname} -> {sig.service}",
                severity=Severity.HIGH, confidence=confidence, module=MODULE_NAME,
                reference=_REFERENCE,
                detail=f"CNAME hacia {cname} ({sig.service}); la respuesta HTTP contiene "
                       f"la huella de recurso no reclamado ('{hit}').{caveat} Verificar "
                       "manualmente antes de dar por confirmada la explotación.",
            )
        break  # respondió algo (no es la huella buscada): no seguir con el otro esquema

    return None  # CNAME apunta a un servicio conocido, pero sin señal de takeover
