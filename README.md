# Nexrecon

Reescritura en Python de Web-Recon (el proyecto original en bash sigue vivo
y es la versión pública con ese nombre). Nexrecon es la versión "de
laboratorio": sin miedo a dependencias, pensada para evolucionar rápido y
para ejercer de pieza de portfolio.

## Por qué Python aquí y bash en el otro proyecto

- **bash** (`Web-Recon`, público): cero fricción de instalación, cualquiera
  lo clona y ejecuta sin gestionar entornos. Correcto para repartir a
  conocidos.
- **Python** (Nexrecon): estructuras de datos reales (dataclasses en vez de
  strings `"a|b|c"`), concurrencia de verdad (`ThreadPoolExecutor` en vez
  de `&`/`wait`), export JSON nativo, comparación de versiones robusta
  (`packaging.version` en vez de `sort -V`), parsing HTML/CSV con librerías
  dedicadas en vez de `sed`/`awk` frágiles, y feedback en vivo con
  `rich.status()` en cada paso largo.

Las herramientas especializadas (ffuf, subfinder, whatweb, wafw00f, wpscan)
se siguen invocando vía `subprocess` — no tiene sentido reimplementar
motores de fingerprinting o fuzzing maduros.

## Instalación

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .   # para tener el comando `nexrecon` disponible en el PATH
```

Dependencias externas (mismas que la versión bash): `ffuf`, `subfinder`,
`whatweb`, `wafw00f`, `wpscan`, `whois`, `ipinfo` (tu script propio) deben
estar en el PATH.

## Uso

```bash
nexrecon ejemplo.com
# o, sin instalar el paquete:
python3 -m nexrecon.cli ejemplo.com
```

No uses `python -c "from nexrecon.cli import main; main()"` — es un rodeo
innecesario; `-m nexrecon.cli` ya invoca correctamente `argparse` sobre
`sys.argv`.

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

## Nota sobre el entorno de desarrollo

Este paquete se escribió y validó (compilación + pruebas funcionales con
datos simulados) sin acceso completo a red para instalar todas las
dependencias en el entorno de build (`dnspython` y `rich` no se pudieron
probar en caliente ahí). Antes del primer uso real, instala
`requirements.txt` en tu máquina y lanza un escaneo de prueba contra un
target que controles.
