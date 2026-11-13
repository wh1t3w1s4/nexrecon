"""Comparación de postura de seguridad entre el dominio raíz y sus
subdominios.

Mejora respecto al bash: el score se calcula directamente a partir de
los `Finding` ya generados por los demás módulos (headers_cookies,
vuln_db, waf) en vez de volver a ejecutar whatweb/curl/wafw00f una
segunda vez solo para la tabla comparativa. Si ya evaluaste el host
en la Fase 2, reutilizas ese resultado — el bash siempre repetía todo
el trabajo desde cero para cada host comparado.

El score es auditable: cada sumando queda en `host.score_breakdown`.
Un número sin desglose no sirve para priorizar, y con un WAF delante
el riesgo real de una cabecera ausente baja sin desaparecer, así que
esas carencias se ponderan a la mitad en vez de contarse enteras.
"""
from __future__ import annotations

from .. import config
from ..models import SEVERITY_RANK, Finding, HostResult, ScanResult, Severity

_SEVERITY_PENALTY = {
    Severity.CRITICAL: -25,
    Severity.HIGH: -14,
    Severity.MEDIUM: -6,
    Severity.LOW: -2,
    Severity.INFO: 0,
}

_MAX_BONUS = 30
_MAX_PENALTY = -55
_DAMPED_SEVERITIES = (Severity.MEDIUM, Severity.LOW)
_DAMPED_MODULES = ("headers",)


def _csp(host: HostResult) -> str:
    return host.headers.get("content-security-policy", "")


def compute_score(host: HostResult) -> int:
    breakdown: list[tuple[str, int]] = [("base neutral", 60)]
    score = 60

    bonus = 0
    if "strict-transport-security" in host.headers:
        bonus += 8
        breakdown.append(("HSTS presente", 8))
    if "content-security-policy" in host.headers:
        bonus += 10
        breakdown.append(("CSP presente", 10))
    if "x-frame-options" in host.headers or "frame-ancestors" in _csp(host):
        bonus += 7
        breakdown.append(("anti-clickjacking", 7))
    if host.waf:
        bonus += 12
        breakdown.append(("WAF presente", 12))

    if bonus > _MAX_BONUS:
        breakdown.append(("techo de bonificación", _MAX_BONUS - bonus))
        bonus = _MAX_BONUS
    score += bonus

    penalty = 0
    for cookie in host.cookies:
        if cookie.is_fully_protected:
            score += 4
            breakdown.append(("cookie con flags completas", 4))
        elif cookie.has_no_protection:
            penalty -= 12
            breakdown.append(("cookie sin ninguna flag", -12))

    for finding in host.findings:
        value = _SEVERITY_PENALTY.get(finding.severity, 0)
        if not value:
            continue
        if host.waf and finding.module in _DAMPED_MODULES and finding.severity in _DAMPED_SEVERITIES:
            value //= 2
        penalty += value
        breakdown.append((finding.title, value))

    if penalty < _MAX_PENALTY:
        breakdown.append(("techo de penalización", _MAX_PENALTY - penalty))
        penalty = _MAX_PENALTY

    score += penalty
    host.score = max(0, min(100, score))
    host.score_breakdown = breakdown
    return host.score


def top_findings(result: ScanResult, limit: int = 5) -> list[tuple[str, Finding]]:
    """Los `limit` hallazgos más graves de todo el escaneo, con su host."""
    rows: list[tuple[str, Finding]] = []
    for hostname, host in result.hosts.items():
        for finding in host.findings:
            if finding.severity is Severity.INFO:
                continue
            rows.append((hostname, finding))
    rows.sort(key=lambda row: (SEVERITY_RANK[row[1].severity], row[0]))
    return rows[:limit]


def high_severity_findings(result: ScanResult) -> list[tuple[str, Finding]]:
    """Solo HIGH y CRITICAL, de todos los hosts — pensado para el
    resumen ejecutivo final en consola, donde no interesa ver avisos
    LOW/MEDIUM/INFO mezclados con lo realmente urgente.
    """
    rows: list[tuple[str, Finding]] = []
    for hostname, host in result.hosts.items():
        for finding in host.findings:
            if finding.severity in (Severity.HIGH, Severity.CRITICAL):
                rows.append((hostname, finding))
    rows.sort(key=lambda row: SEVERITY_RANK[row[1].severity])
    return rows


def cookie_summary(host: HostResult) -> str:
    if not host.cookies:
        return "sin cookies"
    protected = sum(1 for c in host.cookies if c.is_fully_protected)
    return f"{protected}/{len(host.cookies)} seguras"


def build_comparison_table(root_host: HostResult,
                            sub_hosts: list[HostResult]) -> list[dict]:
    """Devuelve filas listas para render (Markdown o rich.Table), ya
    ordenadas: dominio raíz primero, luego el resto.
    """
    rows = []
    for host in [root_host, *sub_hosts]:
        rows.append({
            "host": host.hostname,
            "score": host.score,
            "hsts": "SI" if "strict-transport-security" in host.headers else "NO",
            "csp": "SI" if "content-security-policy" in host.headers else "NO",
            "xfo": "SI" if (
                "x-frame-options" in host.headers
                or "frame-ancestors" in _csp(host)
            ) else "NO",
            "cookies": cookie_summary(host),
            "waf": "SI" if host.waf else "NO",
            "vulns": len(host.vulns),
        })
    return rows


def weakest_links(root_host: HostResult, sub_hosts: list[HostResult]) -> list[dict]:
    """Hosts cuyo score cae por debajo del umbral respecto al dominio raíz."""
    alerts = []
    for host in sub_hosts:
        gap = root_host.score - host.score
        if gap >= config.POSTURE_GAP_ALERT:
            alerts.append({"hostname": host.hostname, "gap": gap, "score": host.score})
    return sorted(alerts, key=lambda a: -a["gap"])
