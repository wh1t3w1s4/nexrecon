"""Cobertura mínima del bloque de WordPress en el reporte Markdown: las
combinaciones error/timeout+raw/timeout-sin-raw que motivaron el fix de
`waf_wordpress.run_wpscan` (ver tests/test_waf_wordpress.py)."""
from __future__ import annotations

from nexrecon.models import HostResult
from nexrecon.report.markdown_report import _host_section


def _host(wordpress):
    host = HostResult(hostname="t.example")
    host.wordpress = wordpress
    return host


def test_error_wins_even_with_nonempty_raw():
    md = _host_section(_host({
        "error": "Scan Aborted: redirige a http://otro.example",
        "raw": "Scan Aborted: redirige a http://otro.example",
        "timed_out": False,
    }))
    assert "wpscan no completó" in md
    assert "Scan Aborted" in md
    assert "```" not in md  # no se muestra como si fuera salida real


def test_timeout_with_partial_raw_shows_content_with_caveat():
    md = _host_section(_host({
        "error": "", "timed_out": True,
        "raw": "[+] WordPress version 6.0 identified",
    }))
    assert "salida parcial" in md
    assert "WordPress version 6.0 identified" in md
    assert "```" in md


def test_timeout_without_raw_shows_no_results_message():
    md = _host_section(_host({"error": "", "timed_out": True, "raw": ""}))
    assert "se agotó por tiempo" in md
    assert "```" not in md


def test_clean_run_no_findings():
    md = _host_section(_host({"error": "", "timed_out": False, "raw": ""}))
    assert "sin hallazgos relevantes" in md


def test_clean_run_with_content():
    md = _host_section(_host({"error": "", "timed_out": False, "raw": "[+] Finished"}))
    assert "```" in md and "Finished" in md
    assert "salida parcial" not in md
