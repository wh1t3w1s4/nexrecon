"""Orquestador principal. Equivalente al cuerpo del script bash, pero:

- Fases independientes (IP info, subdominios) se paralelizan con
  ThreadPoolExecutor en vez de ejecutarse en fila.
- Cada subdominio vivo se evalúa en paralelo durante la comparación de
  postura (en bash era un `for` secuencial que repetía whatweb+curl+wafw00f
  uno detrás de otro).
- `rich` sustituye a los códigos ANSI manuales para banner, colores y
  la tabla comparativa final (alineación automática, sin el problema de
  ancho de columna con símbolos Unicode que tuvimos en bash).
"""
from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table

from . import config
from .auth import argparse_cookie
from .http_client import HttpClient
from .models import Endpoint, HostResult, ScanResult, Severity
from .modules import (
    active_probes,
    bypass403,
    cors,
    dns_recon,
    endpoint_discovery,
    fingerprint,
    fuzzing,
    headers_cookies,
    ip_intel,
    nuclei_scan,
    osv,
    posture,
    searchsploit_scan,
    subdomains,
    takeover,
    vuln_db,
    waf_wordpress,
)
from .report import json_report, markdown_report

console = Console()


def print_banner() -> None:
    console.print("[bold cyan]Nexrecon[/bold cyan] [yellow]v0.3.0[/yellow] — by w1s4\n")


def detect_protocol(client: HttpClient, domain: str) -> str | None:
    for scheme in ("https", "http"):
        status = client.status_only(f"{scheme}://{domain}")
        if 200 <= status < 500:
            return scheme
    return None


def parse_robots(client: HttpClient, base_url: str) -> list[str]:
    """Extrae Allow/Disallow de robots.txt.

    Tolera la ausencia de espacio tras los dos puntos (`Disallow:/admin`),
    comentarios, líneas vacías y respuestas que no son 200 — antes un 404
    se parseaba como si fuera un robots.txt válido.
    """
    result = client.get(f"{base_url}/robots.txt")
    if not result.ok or result.status_code != 200:
        return []

    paths: list[str] = []
    for raw in result.text.splitlines():
        line = raw.split("#", 1)[0].strip()
        directive, sep, value = line.partition(":")
        if not sep or directive.strip().lower() not in ("allow", "disallow"):
            continue
        value = value.strip()
        if value:
            paths.append(value)
    return paths


def run_phase1(client: HttpClient, result: ScanResult, subdomain_mode: bool) -> None:
    console.rule("[bold]Fase 1 — Reconocimiento pasivo[/bold]")

    if not subdomain_mode:
        console.print("[green][+] WHOIS[/green]")
        result.whois_raw = ip_intel.run_whois(result.target)

        console.print("[green][+] Registros DNS[/green]")
        result.dns_records = dns_recon.full_dns_recon(result.target)

        ns_recordset = result.dns_records.get("NS")
        if ns_recordset and ns_recordset.values:
            console.print("[green][+] Probando transferencia de zona (AXFR)[/green]")
            result.axfr_attempted = True
            result.axfr_results = dns_recon.attempt_axfr(result.target, ns_recordset.values)
            if result.axfr_results:
                console.print(
                    f"[bold red][!] AXFR exitoso contra {len(result.axfr_results)} "
                    f"nameserver(s) — zona filtrada[/bold red]"
                )
            else:
                console.print("[dim]  AXFR: sin éxito (configuración correcta)[/dim]")

    console.print("[green][+] Resolución A y geolocalización[/green]")
    ips = dns_recon.resolve_a(result.target)
    result.ip_addresses = ips[: config.MAX_IPS_TO_ANALYZE]

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            pool.submit(ip_intel.gather_ip_intel, client, ip): ip
            for ip in result.ip_addresses
        }
        for future in as_completed(futures):
            intel = future.result()
            result.ip_intel.append(intel)
            hosting_label = (
                "hosting/datacenter" if intel.is_hosting is True
                else "no-hosting (posible IP directa/residencial)" if intel.is_hosting is False
                else "sin determinar"
            )
            cdn_note = f" — CDN: {intel.cdn_provider}" if intel.cdn_provider else ""
            console.print(f"[dim]  {intel.ip}: {hosting_label}{cdn_note}[/dim]")


def evaluate_host(client: HttpClient, hostname: str, protocol: str | None = None,
                  run_fuzzing: bool = True, verbose: bool = True,
                  deep: bool = False, use_nuclei: bool = False,
                  active_probes_on: bool = False, manual_param: Endpoint | None = None) -> HostResult:
    """Ejecuta todos los módulos de Fase 2 contra un host.

    `protocol=None` hace que se detecte por host: un subdominio puede
    servir solo HTTP aunque el dominio raíz vaya por HTTPS, y antes se
    evaluaba con el esquema equivocado.

    `verbose=True` (por defecto, usado para el host raíz) muestra un
    spinner por paso con console.status() — mismo propósito que el
    patrón de spinner que montamos a mano en bash para wpscan, aquí
    viene integrado en rich. `verbose=False` se usa al evaluar los
    subdominios en paralelo, donde un spinner por hilo generaría ruido
    visual superpuesto; ahí solo se imprime el resultado final de cada uno.

    `deep=True` (flag -d/--deep) usa la wordlist grande (big.txt en vez
    de common.txt) con más margen de tiempo, y wpscan en modo "mixed"
    (barrido activo) en vez de "passive". `use_nuclei=True` (flag
    --nuclei, o automático bajo --deep) añade un escaneo de templates
    de nuclei — la pieza más ruidosa de todas, por eso nunca se activa
    por defecto.
    """
    if protocol is None:
        protocol = detect_protocol(client, hostname)
        if protocol is None:
            host = HostResult(hostname=hostname)
            host.add_finding("El host no responde por HTTP ni HTTPS",
                             Severity.INFO, module="cli")
            posture.compute_score(host)
            return host

    host = HostResult(hostname=hostname, protocol=protocol)
    base_url = f"{protocol}://{hostname}"

    def step(label: str, fn, *args):
        if verbose:
            with console.status(f"[cyan]{label}...[/cyan]"):
                return fn(*args)
        return fn(*args)

    cookie_header = client.auth.header if client.auth else None

    ww_output = step("Fingerprinting (whatweb)", fingerprint.run_whatweb, base_url, cookie_header)
    if fingerprint.is_cloudflare_block(ww_output):
        host.add_finding("Cloudflare challenge detectado", Severity.INFO,
                          "whatweb omitido para este host.", module="whatweb")
        if verbose:
            console.print("[yellow][-] Cloudflare detectado, whatweb omitido[/yellow]")
    else:
        host.technologies = fingerprint.extract_technologies(ww_output)
        if verbose and host.technologies:
            techs = ", ".join(
                f"{k} {v}".strip() for k, v in host.technologies.items()
            )
            console.print("[green][+] Tecnologías:[/green]", techs)

    step("Analizando cabeceras y cookies", headers_cookies.analyze, client, host, base_url)
    cors_findings = step("Comprobando CORS", cors.check, client, host, base_url)
    host.findings.extend(cors_findings)
    if verbose and cors_findings:
        console.print(f"[red][!] CORS: {len(cors_findings)} hallazgo(s)[/red]")
    host.vulns = vuln_db.check_technologies(host)
    if config.OSV_ENABLED:
        static_cves = {c.strip() for v in host.vulns for c in v.cve.split(",")}
        host.vulns += step("Consultando OSV.dev", osv.enrich, client, host, static_cves)
    if verbose:
        if host.vulns:
            console.print(f"[red][!] {len(host.vulns)} vulnerabilidad(es) conocidas por versión[/red]")
        else:
            console.print("[green][+] Sin vulnerabilidades conocidas por versión[/green]")

    # searchsploit consulta una base offline (sin tráfico hacia el target),
    # por eso corre siempre y no va gateado tras --deep.
    exploit_findings = step(
        "Buscando exploits públicos (searchsploit)",
        searchsploit_scan.gather_exploits_for_host, host,
    )
    host.findings.extend(exploit_findings)
    if verbose:
        confirmed, total = searchsploit_scan.count_exploits(host)
        if total:
            console.print(
                f"[red][!] searchsploit: {total} exploit(s) público(s) "
                f"({confirmed} confirmado(s) por CVE)[/red]"
            )
        elif not searchsploit_scan.searchsploit_available():
            console.print("[yellow][-] searchsploit no encontrado, se omite[/yellow]")
        else:
            console.print("[green][+] searchsploit: sin exploits públicos[/green]")

    host.waf = step("Detectando WAF", waf_wordpress.detect_waf, base_url)
    if verbose:
        console.print("[green][+] WAF:[/green]", host.waf or "no detectado")

    if waf_wordpress.is_wordpress(ww_output):
        if not waf_wordpress.wpscan_available():
            host.add_finding("wpscan no está instalado, se omite", Severity.INFO,
                              "Instálalo con: gem install wpscan", module="wordpress")
            if verbose:
                console.print("[yellow][-] wpscan no encontrado, se omite[/yellow]")
        else:
            if deep and not config.WPSCAN_API_TOKEN:
                console.print(
                    "[bold yellow][!] --deep sin WPSCAN_API_TOKEN: wpscan no podrá "
                    "cruzar contra la base de datos de CVEs de WPScan, solo detectará "
                    "plugins/temas/usuarios sin marcar cuáles son vulnerables.[/bold yellow]"
                )
                console.print(
                    "[dim]    Consigue uno gratis en https://wpscan.com/ y expórtalo: "
                    "export WPSCAN_API_TOKEN=\"...\"[/dim]"
                )
                host.add_finding(
                    "wpscan sin API token en modo --deep", Severity.INFO,
                    "Sin WPSCAN_API_TOKEN no se identifican vulnerabilidades conocidas "
                    "de los plugins/temas detectados, solo su presencia.",
                    module="wordpress",
                )

            update_result = step("Actualizando base de datos de wpscan", waf_wordpress.update_wpscan_db)
            if verbose and not update_result["ok"]:
                console.print(f"[dim]  wpscan --update: {update_result['output'][:120]}[/dim]")

            wp_mode = config.WPSCAN_MODE_DEEP if deep else config.WPSCAN_MODE_DEFAULT
            wp_timeout = config.WPSCAN_TIMEOUT_DEEP if deep else config.WPSCAN_TIMEOUT_DEFAULT
            if verbose:
                console.print(
                    f"[green][+] WordPress detectado, lanzando wpscan en modo "
                    f"'{wp_mode}' (timeout {wp_timeout}s)[/green]"
                )

            def _on_wpscan_line(line: str, _verbose=verbose) -> None:
                # wpscan usa \r para las barras de progreso en la misma
                # línea; nos quedamos solo con el último fragmento, que
                # es lo que un terminal real mostraría.
                display = line.split("\r")[-1].strip()
                if _verbose and display.startswith(("[+]", "[i]", "[!]")):
                    console.print(f"  [dim cyan]{display}[/dim cyan]")

            host.wordpress = waf_wordpress.run_wpscan(
                base_url, wp_timeout, wp_mode,
                on_line=_on_wpscan_line if verbose else None,
                cookie_header=cookie_header,
            )

            # Superficie explícita del resultado: antes un timeout o un fallo
            # de wpscan quedaba indistinguible de "corrió bien y no encontró
            # nada", y en el reporte salía un bloque vacío sin explicación.
            #
            # "error" (incluye el autoaborto de wpscan, p. ej. por redirect) es
            # excluyente: si wpscan decidió que no pudo escanear de verdad, eso
            # manda aunque haya impreso algo de texto. "timed_out" en cambio NO
            # es excluyente con tener "raw": un timeout que SÍ capturó salida
            # real antes del corte se procesa igual que un escaneo completo,
            # solo que avisando de que es parcial — antes se tiraba esa salida
            # entera por error (ver `run_wpscan`).
            raw = host.wordpress.get("raw", "")
            if host.wordpress.get("error"):
                host.add_finding(
                    "wpscan falló", Severity.INFO, host.wordpress["error"], module="wordpress",
                )
                if verbose:
                    console.print(f"[yellow][-] wpscan: {host.wordpress['error']}[/yellow]")
            else:
                if host.wordpress.get("timed_out"):
                    detail = (
                        f"Se agotó el tiempo ({wp_timeout}s) " +
                        ("pero se capturó salida parcial antes del corte — ver detalle abajo."
                         if raw else "sin ninguna salida capturada.") +
                        " Prueba con --deep (más timeout) o revisa la conexión al target."
                    )
                    host.add_finding("wpscan se agotó por tiempo", Severity.INFO, detail, module="wordpress")
                    if verbose:
                        estado = "con salida parcial" if raw else "sin resultados"
                        console.print(f"[yellow][-] wpscan: timeout a los {wp_timeout}s, {estado}[/yellow]")

                if verbose:
                    if raw:
                        console.print(f"[green][+] wpscan: {len(raw.splitlines())} líneas de salida (ver reporte)[/green]")
                    elif not host.wordpress.get("timed_out"):
                        console.print("[dim]  wpscan: sin hallazgos relevantes en modo passive[/dim]")

                # Clasificación de usuarios/backups en hallazgos reales,
                # no solo texto suelto dentro del bloque de wpscan.
                wp_findings = waf_wordpress.extract_wordpress_findings(host.wordpress.get("lines", []))
                severity_map = {"medium": Severity.MEDIUM, "low": Severity.LOW, "critical": Severity.CRITICAL}
                for wf in wp_findings:
                    host.add_finding(
                        wf["title"], severity_map.get(wf["severity"], Severity.INFO),
                        wf["detail"], module="wordpress",
                    )
                if verbose and wp_findings:
                    users = sum(1 for f in wp_findings if f["kind"] == "user")
                    backups = sum(1 for f in wp_findings if f["kind"] == "config_backup")
                    if users:
                        console.print(f"[yellow][!] {users} usuario(s) de WordPress identificado(s)[/yellow]")
                    if backups:
                        console.print(f"[bold red][!] {backups} posible(s) backup(s) de configuración expuesto(s)[/bold red]")

            if host.wordpress.get("db_outdated"):
                host.add_finding(
                    "Base de datos de wpscan desactualizada", Severity.INFO,
                    "Actualízala con: wpscan --update", module="wordpress",
                )
                if verbose:
                    console.print("[yellow][!] wpscan avisa de BD desactualizada — ejecuta: wpscan --update[/yellow]")

    if use_nuclei:
        if not nuclei_scan.nuclei_available():
            host.add_finding("nuclei no está instalado, se omite", Severity.INFO,
                              "Instálalo con: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                              module="nuclei")
            if verbose:
                console.print("[yellow][-] nuclei no encontrado, se omite[/yellow]")
        else:
            if verbose:
                console.print("[green][+] Ejecutando nuclei (puede tardar varios minutos)[/green]")
            raw_nuclei = step("nuclei en curso", nuclei_scan.run_nuclei, base_url,
                               config.NUCLEI_MAX_SECONDS, cookie_header)
            nuclei_findings = nuclei_scan.findings_from_nuclei(raw_nuclei)
            host.findings.extend(nuclei_findings)
            if verbose:
                if nuclei_findings:
                    console.print(f"[red][!] nuclei: {len(nuclei_findings)} hallazgo(s)[/red]")
                else:
                    console.print("[green][+] nuclei: sin hallazgos[/green]")

    if run_fuzzing:
        wordlist = config.WORDLIST_DEEP if deep else config.WORDLIST_DEFAULT
        max_seconds = config.FFUF_MAX_SECONDS_DEEP if deep else config.FFUF_MAX_SECONDS
        if verbose:
            console.print(
                f"[green][+] Iniciando fuzzing de directorios con "
                f"{Path(wordlist).name} a {config.FFUF_THREADS_DEFAULT} hilos (puede tardar)[/green]"
            )
        try:
            run = step("Fuzzing con ffuf", fuzzing.fuzz, base_url, wordlist, max_seconds,
                       cookie_header)
        except FileNotFoundError as exc:
            run = fuzzing.FuzzRun(results=[])
            host.add_finding("Fuzzing omitido", Severity.INFO, str(exc), module="fuzzing")
            if verbose:
                console.print(f"[yellow][-] Fuzzing omitido: {exc}[/yellow]")

        if run.truncated:
            host.add_finding(
                "Fuzzing truncado por tiempo", Severity.INFO,
                f"ffuf se detuvo a los {max_seconds}s; el listado puede estar incompleto.",
                module="fuzzing",
            )

        if run.retried_with_fewer_threads:
            host.add_finding(
                "Posible rate-limit durante el fuzzing", Severity.INFO,
                f"{run.rate_limit_hits_first_pass} respuestas de bloqueo "
                f"(429/500/502/503/504/508) con {config.FFUF_THREADS_DEFAULT} hilos; "
                f"se reintentó con {config.FFUF_THREADS_THROTTLED}. Si persiste, "
                "considera bajar FFUF_THREADS_DEFAULT para ser más sigiloso.",
                module="fuzzing",
            )
            if verbose:
                console.print(
                    f"[yellow][!] Rate-limit detectado ({run.rate_limit_hits_first_pass} "
                    f"respuestas de bloqueo), reintentado con {config.FFUF_THREADS_THROTTLED} hilos[/yellow]"
                )

        clean, suspicious, forbidden = fuzzing.classify_results(run.results)
        host.directories_clean = clean
        host.directories_suspicious = suspicious
        if verbose:
            console.print(
                f"[green][+] {len(clean)} resultados limpios, "
                f"{len(suspicious)} descartados como ruido[/green]"
            )

        if forbidden:
            if deep:
                if verbose:
                    console.print(f"[yellow][!] Probando bypass sobre {len(forbidden)} rutas con 403[/yellow]")
                bypass_hits = []
                for url in forbidden:
                    path = url.replace(base_url, "", 1)
                    bypass_hits += bypass403.test_bypass(client, base_url, path)
                host.forbidden_bypassed = bypass_hits
                if verbose and bypass_hits:
                    console.print(f"[red][!] {len(bypass_hits)} bypass(es) conseguidos[/red]")
            else:
                host.add_finding(
                    f"{len(forbidden)} ruta(s) con 403 detectadas", Severity.INFO,
                    "Ejecuta con -d/--deep para intentar técnicas de bypass automáticamente.",
                    module="fuzzing",
                )
                if verbose:
                    console.print(
                        f"[dim]  {len(forbidden)} rutas con 403 — usa -d/--deep "
                        f"para intentar bypass automático[/dim]"
                    )

    # Solo lectura (tope de ~35 GET): formularios, enlaces con query y JS propio.
    disc_findings = step(
        "Descubriendo endpoints (formularios, enlaces, JS propio)",
        endpoint_discovery.discover, client, host, base_url,
    )
    host.findings.extend(disc_findings)
    if active_probes_on:
        if verbose:
            console.print("[bold yellow][!] active-probes: enviando payloads de detección...[/bold yellow]")
        probe_findings = step(
            "Sondas activas (SQLi/XSS/SSTI/IDOR/SSRF)",
            active_probes.run, client, host, manual_param,
        )
        host.findings.extend(probe_findings)
        if verbose:
            real_findings = [f for f in probe_findings if f.severity != Severity.INFO]
            for f in probe_findings:
                if f.severity == Severity.INFO:
                    console.print(f"[yellow][-] active-probes: {f.title}[/yellow]")
            if real_findings:
                console.print(
                    f"[bold red][!] active-probes: {len(real_findings)} señal(es) a revisar manualmente[/bold red]"
                )
            elif not probe_findings:
                console.print("[green][+] active-probes: sin hallazgos[/green]")

    if verbose:
        by_source: dict[str, int] = {}
        for ep in host.endpoints:
            by_source[ep.source] = by_source.get(ep.source, 0) + 1
        summary = ", ".join(f"{n} {src}" for src, n in sorted(by_source.items())) or "ninguno"
        console.print(f"[green][+] Endpoints descubiertos:[/green] {len(host.endpoints)} ({summary})")
        for f in disc_findings:
            console.print(f"[bold red][!] {f.title}[/bold red]")

    posture.compute_score(host)
    if verbose:
        console.print(f"[bold green][+] Score de postura: {host.score}/100[/bold green]")
    return host


def run_phase2(client: HttpClient, result: ScanResult, subdomain_mode: bool,
               deep: bool = False, use_nuclei: bool = False,
               active_probes_on: bool = False, manual_param: Endpoint | None = None) -> None:
    console.rule("[bold]Fase 2 — Reconocimiento activo[/bold]")

    protocol = detect_protocol(client, result.target)
    if not protocol:
        console.print(f"[yellow][-] {result.target} no responde por HTTP ni HTTPS[/yellow]")
        return

    console.print(f"[green][+] Protocolo detectado: {protocol}[/green]\n")
    root_host = evaluate_host(client, result.target, protocol,
                               deep=deep, use_nuclei=use_nuclei,
                               active_probes_on=active_probes_on, manual_param=manual_param)
    result.hosts[result.target] = root_host

    if result.axfr_results:
        for ns, records in result.axfr_results.items():
            root_host.add_finding(
                f"Transferencia de zona (AXFR) exitosa contra {ns}",
                Severity.CRITICAL,
                f"{len(records)} registros de la zona expuestos sin autenticación.",
                module="dns",
            )
        posture.compute_score(root_host)

    result.robots_paths = parse_robots(client, f"{protocol}://{result.target}")

    root_takeover = takeover.check_host(client, result.target)
    if root_takeover:
        root_host.findings.append(root_takeover)
        posture.compute_score(root_host)
        console.print(f"[bold red][!] {root_takeover.title}[/bold red]")

    if subdomain_mode:
        return

    console.rule("Descubrimiento de subdominios")
    with ThreadPoolExecutor(max_workers=3) as pool:
        f_subfinder = pool.submit(subdomains.run_subfinder, result.target)
        f_crtsh = pool.submit(subdomains.query_crtsh, client, result.target)
        f_shodan = pool.submit(subdomains.scrape_shodan, client, result.target)
        subs_sf, subs_crt, subs_sh = (
            f_subfinder.result(), f_crtsh.result(), f_shodan.result()
        )

    result.subdomain_sources = {
        "subfinder": subs_sf, "crt.sh": subs_crt, "shodan": subs_sh,
    }
    result.subdomains_merged = subdomains.merge_sources(
        result.target, subs_sf, subs_crt, subs_sh
    )
    console.print(f"[green][+] {len(result.subdomains_merged)} subdominios únicos[/green]")

    result.subdomains_alive = subdomains.check_alive(
        client, result.subdomains_merged, protocol
    )
    console.print(f"[green][+] {len(result.subdomains_alive)} subdominios vivos[/green]")

    with (
        console.status(
            f"[blue]Evaluando subdomain takeover en {len(result.subdomains_merged)} "
            "subdominios...[/blue]"
        ),
        ThreadPoolExecutor(max_workers=10) as pool,
    ):
        futures = {
            pool.submit(takeover.check_host, client, sub): sub
            for sub in result.subdomains_merged
        }
        for future in as_completed(futures):
            sub = futures[future]
            finding = future.result()
            if finding:  # asignación a result.hosts en el hilo principal
                host = result.get_or_create_host(sub)
                host.findings.append(finding)
                posture.compute_score(host)
                console.print(f"[bold red][!] {finding.title}[/bold red]")

    if not result.subdomains_alive:
        return

    console.rule("Comparación de postura de seguridad")
    if use_nuclei:
        console.print("[dim]  (nuclei solo se ejecuta sobre el dominio raíz)[/dim]")
    # Un subdominio puede tener YA un hallazgo de takeover (y por tanto un
    # HostResult provisional en result.hosts) y además responder a HTTP, con
    # lo que también pasa por evaluate_host completo. Sin esto, la línea de
    # abajo lo sobrescribiría y se perdería el hallazgo de takeover.
    pending_findings = {
        h: list(result.hosts[h].findings)
        for h in result.subdomains_alive if h in result.hosts
    }
    with (
        console.status(f"[cyan]Evaluando {len(result.subdomains_alive)} subdominios en paralelo...[/cyan]"),
        ThreadPoolExecutor(max_workers=6) as pool,
    ):
        futures = {
            pool.submit(evaluate_host, client, sub, None, True, False, deep, False): sub
            for sub in result.subdomains_alive
        }
        for future in as_completed(futures):
            host = future.result()
            extra = pending_findings.get(host.hostname)
            if extra:
                host.findings.extend(extra)
                posture.compute_score(host)
            result.hosts[host.hostname] = host
            console.print(f"[dim]  ✓ {host.hostname} (score {host.score})[/dim]")

    sub_hosts = [result.hosts[h] for h in result.subdomains_alive]
    render_posture_table(root_host, sub_hosts)

    alerts = posture.weakest_links(root_host, sub_hosts)
    for alert in alerts:
        console.print(
            f"[bold red][!] {alert['hostname']}: {alert['gap']} puntos por debajo "
            f"del dominio raíz (score {alert['score']}) — revisar como prioridad[/bold red]"
        )


def render_posture_table(root_host: HostResult, sub_hosts: list[HostResult]) -> None:
    rows = posture.build_comparison_table(root_host, sub_hosts)
    table = Table(title="Postura de seguridad: dominio raíz vs subdominios")
    for col in ("Host", "Score", "HSTS", "CSP", "XFO", "Cookies", "WAF", "Vulns", "Exploits"):
        table.add_column(col)
    for row in rows:
        table.add_row(
            row["host"], str(row["score"]), row["hsts"], row["csp"],
            row["xfo"], row["cookies"], row["waf"], str(row["vulns"]), row["exploits"],
        )
    console.print(table)


def build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nexrecon", description="Nexrecon — reconocimiento web automatizado"
    )
    parser.add_argument("target", help="Dominio o subdominio objetivo")
    parser.add_argument("-o", "--output", default=config.DEFAULT_OUTPUT_DIR,
                         help="Carpeta base de resultados")
    parser.add_argument("-n", "--no-export", action="store_true",
                         help="No exportar a disco, solo mostrar en pantalla")
    parser.add_argument("-s", "--subdomain", action="store_true",
                         help="Modo subdominio: omite WHOIS/DNS extra/descubrimiento")
    parser.add_argument("-d", "--deep", action="store_true",
                         help="Modo intensivo: wordlist grande, wpscan mixed y nuclei automático")
    parser.add_argument("--nuclei", action="store_true",
                         help="Ejecuta nuclei sobre el dominio raíz (ruidoso). "
                              "Implícito con -d/--deep")
    parser.add_argument("--no-osv", action="store_true",
                         help="Desactiva la consulta a OSV.dev. Útil en redes air-gapped/offline")
    parser.add_argument("--active-probes", action="store_true",
                         help="Sondas de detección activa (SQLi/XSS/SSTI/IDOR/SSRF/open "
                              "redirect/LFI). Nunca marca nada como explotado")
    parser.add_argument("--param", type=active_probes.argparse_param, metavar='"URL?PARAM="',
                         help="Ejecuta --active-probes apuntando solo a esta URL/parámetro "
                              "(ej. \"https://target.com/search?q=\")")
    parser.add_argument("--cookie", type=argparse_cookie, metavar='"NOMBRE=VALOR; ..."',
                         help="Recon autenticado: cookies de sesión a enviar al objetivo. "
                              "No aparecen en los reportes")
    return parser


def write_reports(result: ScanResult, output_dir: str, secrets: list[str] | None = None) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_target = result.target.replace("/", "_")
    outdir = Path(output_dir) / f"{safe_target}_{timestamp}"
    outdir.mkdir(parents=True, exist_ok=True)

    markdown_report.write_markdown(result, outdir / "reporte_final.md", secrets)
    json_report.write_json(result, outdir / "reporte_final.json", secrets)

    # Mismo patrón que la versión bash: ficheros sueltos además del
    # reporte completo, para quien quiera un `cat`/`grep` rápido sin
    # abrir el Markdown entero.
    if result.subdomains_alive:
        (outdir / "subdominios_vivos.txt").write_text(
            "\n".join(result.subdomains_alive), encoding="utf-8"
        )

    root_host = result.hosts.get(result.target)
    if root_host and root_host.wordpress and root_host.wordpress.get("raw"):
        (outdir / "wordpress.txt").write_text(root_host.wordpress["raw"], encoding="utf-8")

    console.print(f"\n[green][+] Reporte guardado en: {outdir}[/green]")

def render_summary(result: ScanResult) -> None:
    """Lo mínimo que quieres ver sin tener que abrir el reporte: IPs,
    hallazgos HIGH/CRITICAL, subdominios vivos, y si hubo WordPress.
    Se imprime siempre que haya algo que contar, incluso con -n.
    """
    console.rule("[bold]Resumen ejecutivo[/bold]")

    if result.ip_addresses:
        console.print(f"[bold]IPs:[/bold] {', '.join(result.ip_addresses)}")
        for intel in result.ip_intel:
            hosting_label = (
                "hosting/datacenter" if intel.is_hosting is True
                else "no-hosting" if intel.is_hosting is False
                else "sin determinar"
            )
            cdn_note = f" [bold yellow](CDN: {intel.cdn_provider})[/bold yellow]" if intel.cdn_provider else ""
            console.print(f"  [dim]{intel.ip}: {hosting_label}[/dim]{cdn_note}")

    root_host = result.hosts.get(result.target)
    if root_host:
        console.print(f"[bold]Score dominio raíz:[/bold] {root_host.score}/100")

    if result.axfr_results:
        console.print(
            f"[bold red]AXFR filtrado contra {len(result.axfr_results)} nameserver(s)[/bold red]"
        )

    high = posture.high_severity_findings(result)
    if high:
        console.print(f"\n[bold]Hallazgos HIGH/CRITICAL ({len(high)}):[/bold]")
        for hostname, finding in high:
            console.print(
                f"  [bold]{finding.severity.value.upper()}[/bold] "
                f"{finding.title} [dim]({hostname}, confianza: {finding.confidence.value})[/dim]"
            )
    else:
        console.print("\n[green]Sin hallazgos HIGH/CRITICAL[/green]")

    if result.subdomains_alive:
        console.print(
            f"\n[bold]Subdominios vivos ({len(result.subdomains_alive)}):[/bold] "
            f"{', '.join(result.subdomains_alive)}"
        )

    for hostname, host in result.hosts.items():
        if not host.wordpress:
            continue
        wp = host.wordpress
        if wp.get("error"):
            console.print(f"\n[yellow]WordPress ({hostname}): wpscan no completó — {wp['error']}[/yellow]")
        elif wp.get("raw"):
            parcial = " (parcial, se agotó el tiempo antes de terminar)" if wp.get("timed_out") else ""
            console.print(
                f"\n[bold]WordPress ({hostname}):[/bold] wpscan generó salida{parcial} "
                f"— ver wordpress.txt / reporte_final.md para detalle "
                f"(usuarios/plugins no se parsean aún de forma estructurada)"
            )
        elif wp.get("timed_out"):
            console.print(
                f"\n[yellow]WordPress ({hostname}): wpscan no completó — "
                f"timeout a los {config.WPSCAN_TIMEOUT_DEFAULT}s[/yellow]"
            )

def main() -> None:
    # El banner va ANTES de parsear: si falta `target` o se pasa -h/--help,
    # argparse corta la ejecución dentro de parse_args() y nunca llegaría
    # a imprimirse si estuviera después.
    print_banner()
    args = build_argparser().parse_args()

    if args.no_osv:
        config.OSV_ENABLED = False

    auth = args.cookie  # None si no se pasó --cookie
    client = HttpClient(auth=auth, scope_domain=args.target if auth else None)
    active_probes_on = args.active_probes or args.param is not None
    result = ScanResult(target=args.target, mode="subdomain" if args.subdomain else "full",
                        authenticated=auth is not None,
                        cookie_names=auth.names if auth else [],
                        active_probes_used=active_probes_on)
    if auth:
        console.print(f"[bold yellow][!] Recon autenticado[/bold yellow] — cookies: {', '.join(auth.names)} "
                      "[dim](valores no se muestran ni se guardan)[/dim]\n")
    if active_probes_on:
        console.print(
            "[bold red][!] --active-probes activo[/bold red] — se enviarán payloads de "
            "detección (nunca de explotación) contra el dominio raíz.\n"
        )
    exit_code = 0

    try:
        run_phase1(client, result, args.subdomain)
        run_phase2(client, result, args.subdomain,
                   deep=args.deep, use_nuclei=args.nuclei or args.deep,
                   active_probes_on=args.active_probes or args.param is not None,
                   manual_param=args.param)
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Interrumpido por el usuario[/bold red]")
        exit_code = 130
    except Exception:
        console.print_exception()
        exit_code = 1
    finally:
        result.finish()
        client.close()
        render_summary(result)
        if args.no_export:
            console.print("\n[dim]Exportación desactivada (-n)[/dim]")
        else:
            try:
                write_reports(result, args.output, auth.secrets() if auth else None)
            except OSError as exc:
                console.print(f"[red][!] No se pudo escribir el reporte: {exc}[/red]")

    if exit_code:
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
