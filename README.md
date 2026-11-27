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
| `--nuclei` | Ejecuta nuclei sobre el dominio raíz (ruidoso). Implícito con `-d/--deep` |
| `--cookie "A=1; B=2"` | Recon autenticado: envía esas cookies solo al dominio objetivo y sus subdominios (también a ffuf, whatweb, nuclei y wpscan). Los valores nunca se guardan en los reportes, solo los nombres |
| `--active-probes` | Sondas de DETECCIÓN activa (SQLi/XSS/SSTI/IDOR/SSRF) sobre los endpoints descubiertos. Nunca por defecto; eje independiente de `-d/--deep`. Solo sobre el dominio raíz, nunca por subdominio. Ningún hallazgo se marca como explotado, solo como señal a verificar manualmente |
| `--param "URL?PARAM="` | Modo manual de `--active-probes`: apunta solo a esa URL/parámetro en vez de usar los endpoints descubiertos automáticamente. Implica `--active-probes` |

## Qué incluye ya

- Fase 1: WHOIS, DNS (A/MX/NS/TXT/SOA/CNAME/CAA con interpretación), IP + Shodan InternetDB.
- Fase 2: protocolo, whatweb + VULN_DB, cabeceras/cookies con `Finding` tipados,
  WAF, WordPress/wpscan, fuzzing con filtrado de ruido vía `Counter`, bypass
  de 403 en paralelo, robots.txt, subdominios (subfinder + crt.sh + scraping
  de Shodan vía BeautifulSoup), comparación de postura de seguridad con
  tabla `rich` y detección de eslabón débil.
- `searchsploit` (base offline de exploit-db) sobre CVEs confirmados por
  `VULN_DB` y por tecnología detectada.
- Descubrimiento de endpoints: formularios HTML, enlaces con query, JS
  propio del host (nunca de terceros) y detección de `.js.map` expuestos.
- Recon autenticado (`--cookie`): sesión acotada al dominio objetivo,
  nunca se guardan los valores en los reportes.
- `--active-probes`: sondas de detección (no explotación) de SQLi, XSS
  reflejado, SSTI, IDOR y candidatos a SSRF sobre los endpoints descubiertos.
- Integración opcional con `nuclei` (`--nuclei`/`-d`).
- Export a Markdown y JSON.
- Feedback en vivo (spinners `rich.status()`) en cada paso largo del host
  raíz: whatweb, cabeceras, WAF, wpscan, fuzzing, bypass de 403, sondas
  activas — para que nunca parezca "colgado" durante varios minutos sin
  explicación.
- Tests (`python3 -m pytest tests`) y CI con ruff (`.github/workflows/ci.yml`).

## Pendiente / próximos pasos

- Modo batch (varios targets en un fichero).
- Logging estructurado a fichero, separado del output en pantalla.
- Iterar `--active-probes` y el descubrimiento de endpoints con uso real
  en labs (pentest-tools, PortSwigger): el primer filtro no es perfecto.
