"""Export a Markdown, legible y con jerarquía, igual que el reporte_final.md
del bash pero construido a partir de objetos estructurados en vez de ir
concatenando strings con \n a mano en cada punto del script.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from ..models import SEVERITY_RANK, HostResult, ScanResult, Severity
from ..modules import posture

_SEVERITY_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


def _host_section(host: HostResult) -> str:
    lines = [f"### {host.hostname}", ""]
    lines.append(f"**Score de postura:** {host.score}/100\n")

    if host.technologies:
        lines.append("**Tecnologías detectadas:**")
        for tech, version in host.technologies.items():
            lines.append(f"- {f'{tech} {version}'.strip()}")
        lines.append("")

    if host.waf:
        lines.append(f"**WAF detectado:** {host.waf}\n")

    if host.vulns:
        lines.append("**Vulnerabilidades por versión:**\n")
        for vuln in host.vulns:
            lines.append(f"- **{vuln.cve}** — {vuln.technology} {vuln.detected_version} "
                         f"(corregido en {vuln.fixed_in})")
            if vuln.description:
                lines.append(f"  {vuln.description}")
            if vuln.reference:
                lines.append(f"  Ref: {vuln.reference}")
        lines.append("")

    if host.findings:
        lines.append("**Hallazgos:**\n")
        lines.append(
            "_Nota: \"Vulnerabilidades por versión\" (arriba) es exclusivamente "
            "VULN_DB; esta lista mezcla el resto de módulos (cabeceras, cookies, "
            "WAF, DNS/AXFR, fuzzing y nuclei si se usó --nuclei/--deep), "
            "identificados entre corchetes._\n"
        )
        for finding in sorted(host.findings,
                              key=lambda f: SEVERITY_RANK.get(f.severity, 9)):
            icon = _SEVERITY_ICON.get(finding.severity, "")
            module_tag = f" `[{finding.module}]`" if finding.module else ""
            lines.append(f"- {icon} **[{finding.severity.value.upper()}] {finding.title}**{module_tag}")
            if finding.detail:
                lines.append(f"  {finding.detail}")
            if finding.reference:
                lines.append(f"  Ref: {finding.reference}")
        lines.append("")

    if host.score_breakdown:
        lines.append("<details><summary>Desglose del score</summary>")
        lines.append("")
        for label, value in host.score_breakdown:
            lines.append(f"- {label}: {value:+d}")
        lines.append("")
        lines.append("</details>")
        lines.append("")

    if host.directories_clean:
        lines.append(f"**Directorios encontrados ({len(host.directories_clean)}):**")
        lines.append("```")
        for hit in host.directories_clean:
            lines.append(f"[{hit.status}] {hit.url}")
        lines.append("```\n")

    if host.forbidden_bypassed:
        lines.append("**Bypass de 403 con éxito:**")
        lines.append("```")
        for item in host.forbidden_bypassed:
            lines.append(f"[{item['status']}] {item['detail']}")
        lines.append("```\n")

    if host.wordpress:
        lines.append("**WordPress (wpscan):**\n")
        if host.wordpress.get("timed_out"):
            lines.append("_wpscan se agotó por tiempo antes de completar — sin resultados._\n")
        elif host.wordpress.get("error"):
            lines.append(f"_wpscan no completó: {host.wordpress['error']}_\n")
        elif host.wordpress.get("raw"):
            lines.append("```")
            lines.append(host.wordpress["raw"][:4000])
            lines.append("```\n")
        else:
            lines.append("_wpscan corrió correctamente, sin hallazgos relevantes en modo passive._\n")

    return "\n".join(lines)


def _executive_summary(result: ScanResult, limit: int = 5) -> list[str]:
    lines = ["## Resumen ejecutivo", ""]

    counts = Counter(
        finding.severity
        for host in result.hosts.values() for finding in host.findings
    )
    if not counts:
        lines += ["Sin hallazgos registrados.", "", "---", ""]
        return lines

    lines.append("Recuento: " + ", ".join(
        f"{counts[severity]} {severity.value}"
        for severity in sorted(counts, key=lambda s: SEVERITY_RANK[s])
    ))
    lines.append("")

    top = posture.top_findings(result, limit)
    if top:
        lines.append(f"**Top {len(top)} por gravedad:**")
        lines.append("")
        for hostname, finding in top:
            lines.append(f"- **[{finding.severity.value.upper()}] {finding.title}** — `{hostname}`")
        lines.append("")

    lines += ["---", ""]
    return lines


def to_markdown(result: ScanResult) -> str:
    parts = [
        f"# Reporte de reconocimiento — {result.target}",
        "",
        f"**Fecha de inicio:** {result.started_at}",
        f"**Fecha de fin:** {result.finished_at or 'en curso'}",
        f"**Modo:** {result.mode}",
        "",
        "---",
        "",
    ]

    parts += _executive_summary(result)

    if result.whois_raw:
        parts += ["## Fase 1 — Reconocimiento pasivo", "", "### WHOIS", "```",
                   result.whois_raw, "```", ""]

    if result.dns_records:
        parts += ["### Registros DNS", ""]
        for rtype, recordset in result.dns_records.items():
            parts.append(f"**{rtype}**")
            if not recordset.values:
                parts.append("_(sin registros)_\n")
                continue
            for value in recordset.values:
                note = recordset.annotations.get(value)
                if note:
                    parts.append(f"- `{value}` → {note}")
                else:
                    parts.append(f"- `{value}`")
            parts.append("")

    if result.axfr_attempted:
        parts.append("**AXFR (transferencia de zona)**")
        parts.append("")
        if result.axfr_results:
            for ns, records in result.axfr_results.items():
                parts.append(f"- ⚠️ Éxito contra `{ns}` — {len(records)} registros filtrados")
            parts.append("")
            parts.append("```")
            for ns, records in result.axfr_results.items():
                parts.append(f"-- {ns} --")
                parts.extend(records[:200])
                if len(records) > 200:
                    parts.append(f"... ({len(records) - 200} registros más, omitidos por longitud)")
            parts.append("```")
        else:
            parts.append("- Sin éxito contra ningún nameserver (configuración correcta)")
        parts.append("")

    if result.ip_addresses:
        parts += ["### IPs y geolocalización", "",
                   f"IPs encontradas: {len(result.ip_addresses)}", "```",
                   "\n".join(result.ip_addresses), "```", ""]
        for intel in result.ip_intel:
            hosting_label = (
                "Sí (hosting/datacenter)" if intel.is_hosting is True
                else "No (posible IP directa/residencial/corporativa)" if intel.is_hosting is False
                else "sin determinar"
            )
            parts.append(f"**{intel.ip}**")
            parts.append(f"- Hosting/Datacenter: {hosting_label}")
            if intel.cdn_provider:
                parts.append(
                    f"- ⚠️ CDN/Proxy detectado: **{intel.cdn_provider}** — "
                    "la IP real del servidor de origen puede diferir de esta."
                )
            if intel.shodan_ports:
                parts.append(f"- Puertos (Shodan): {', '.join(map(str, intel.shodan_ports))}")
            if intel.shodan_cves:
                parts.append(f"- CVEs conocidas (Shodan): {', '.join(intel.shodan_cves)}")
            if intel.ipinfo_summary:
                parts.append("")
                parts.append("```")
                parts.append(intel.ipinfo_summary)
                parts.append("```")
            parts.append("")

    parts += ["---", "", "## Fase 2 — Reconocimiento activo", ""]
    for host in result.hosts.values():
        parts.append(_host_section(host))
        parts.append("---\n")

    # robots.txt pertenece al host raíz: va dentro de la Fase 2, no
    # detrás del bloque de subdominios.
    if result.robots_paths:
        parts += ["### robots.txt (dominio raíz)", "", "```",
                   "\n".join(result.robots_paths), "```", ""]

    if result.subdomains_merged:
        parts += ["---", "", "## Subdominios", "",
                   f"**Total únicos:** {len(result.subdomains_merged)}", ""]
        for source, names in result.subdomain_sources.items():
            parts.append(f"- {source}: {len(names)}")
        parts.append("")
        parts.append("```")
        parts.append("\n".join(result.subdomains_merged))
        parts.append("```\n")

    parts += ["---", "", "*Fin del reporte.*"]
    return "\n".join(parts)


def write_markdown(result: ScanResult, path: Path) -> None:
    path.write_text(to_markdown(result), encoding="utf-8")
