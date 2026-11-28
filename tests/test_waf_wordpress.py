from __future__ import annotations

from nexrecon.modules import waf_wordpress as ww


class FakeProc:
    def __init__(self, lines, returncode=0):
        self.stdout = iter(lines)
        self.returncode = returncode
        self.killed = False

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.killed = True


def _patch_popen(monkeypatch, lines, returncode=0):
    proc = FakeProc(lines, returncode)
    monkeypatch.setattr(ww.subprocess, "Popen", lambda *a, **k: proc)
    return proc


def test_normal_successful_scan(monkeypatch):
    lines = ["[+] WordPress version 6.0 identified", "[+] Finished: Mon 1 Jan 00:00:00 2026"]
    _patch_popen(monkeypatch, lines, returncode=0)
    monkeypatch.setattr(ww.time, "monotonic", lambda: 0)

    result = ww.run_wpscan("http://t.example", timeout=90)
    assert result["timed_out"] is False
    assert result["error"] == ""
    assert "WordPress version 6.0" in result["raw"]


def test_timeout_race_keeps_already_captured_output(monkeypatch):
    # El proceso en realidad YA había producido toda su salida real; el
    # chequeo de tiempo se dispara justo al leer la ÚLTIMA línea (que ya
    # se añadió a `lines` antes del break). No debe tirarse ese contenido.
    lines = ["[+] WordPress version 6.0 identified", "[+] Finished: Mon 1 Jan 00:00:00 2026"]
    _patch_popen(monkeypatch, lines, returncode=0)

    times = iter([0, 10, 95])  # start, chequeo línea 1 (dentro de plazo), chequeo línea 2 (lo supera)
    monkeypatch.setattr(ww.time, "monotonic", lambda: next(times))

    result = ww.run_wpscan("http://t.example", timeout=90)
    assert result["timed_out"] is True
    assert "WordPress version 6.0" in result["raw"]
    assert "Finished" in result["raw"]
    assert result["error"] == ""  # un timeout no es un "error" de proceso


def test_timeout_with_zero_lines_captured(monkeypatch):
    # Sin ninguna línea que iterar, el for-loop ni siquiera entra; esto
    # solo comprueba que "sin salida" sigue devolviendo raw vacío (no una
    # regresión del caso sin contenido).
    _patch_popen(monkeypatch, [], returncode=-9)
    monkeypatch.setattr(ww.time, "monotonic", lambda: 0)
    result = ww.run_wpscan("http://t.example", timeout=90)
    assert result["raw"] == ""
    assert result["timed_out"] is False


def test_scan_aborted_is_reported_as_error_not_success(monkeypatch):
    lines = [
        "[+] URL: http://t.example/",
        "Scan Aborted: The URL supplied redirects to http://other.example/ "
        "Use the --ignore-main-redirect option to ignore the redirection and scan the target.",
    ]
    _patch_popen(monkeypatch, lines, returncode=1)
    monkeypatch.setattr(ww.time, "monotonic", lambda: 0)

    result = ww.run_wpscan("http://t.example", timeout=90)
    assert result["timed_out"] is False
    assert result["error"].startswith("Scan Aborted:")
    assert "ignore-main-redirect" in result["error"]


def test_generic_nonzero_exit_without_output_is_still_an_error(monkeypatch):
    _patch_popen(monkeypatch, [], returncode=2)
    monkeypatch.setattr(ww.time, "monotonic", lambda: 0)
    result = ww.run_wpscan("http://t.example", timeout=90)
    assert result["timed_out"] is False
    assert "código 2" in result["error"]
