# Nexrecon

Reescritura y mejora en Python de [Web-Recon](https://github.com/wh1t3w1s4/Web-Recon).

## Instalación

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .   # para tener el comando `nexrecon` disponible en el PATH
```

Dependencias externas: `ffuf`, `subfinder`,
`whatweb`, `wafw00f`, `wpscan`, `whois`, `ipinfo` deben
estar en el PATH.

## Uso

```bash
nexrecon ejemplo.com
# o, sin instalar el paquete:
python3 -m nexrecon.cli ejemplo.com
```

| Opción | Descripción |
|---|---|
| `-o, --output <ruta>` | Carpeta base de resultados (por defecto `resultados/`) |
| `-n, --no-export` | No exportar a disco |
| `-s, --subdomain` | Modo subdominio: omite WHOIS/DNS extra/descubrimiento |

## Qué incluye ya

- Fase 1: WHOIS, DNS (A/MX/NS/TXT/SOA/CNAME/CAA con interpretación), IP + Shodan InternetDB.
- Fase 2: protocolo, whatweb + VULN_DB, cabeceras/cookies con `Finding` tipados,
  WAF, WordPress/wpscan, fuzzing con filtrado de ruido vía `Counter`, bypass
  de 403 en paralelo, robots.txt, subdominios (subfinder + crt.sh + scraping
  de Shodan vía BeautifulSoup), comparación de postura de seguridad con
  tabla `rich` y detección de eslabón débil.
- Export a Markdown y JSON.
- Feedback en vivo (spinners `rich.status()`) en cada paso largo del host
  raíz: whatweb, cabeceras, WAF, wpscan, fuzzing, bypass de 403 — para que
  nunca parezca "colgado" durante varios minutos sin explicación.

## Pendiente / próximos pasos

- `searchsploit` sobre las tecnologías detectadas.
- Modo batch (varios targets en un fichero).
- Extracción de endpoints desde bundles JS (para SPAs).
- Gestión de sesión/cookies de autenticación para recon post-login.
- Integración con `nuclei`.
- Tests unitarios (pytest) y CI con shellcheck/ruff.
- Logging estructurado a fichero, separado del output en pantalla.
