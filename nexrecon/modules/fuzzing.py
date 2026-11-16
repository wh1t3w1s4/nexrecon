"""Fuzzing de directorios con ffuf + filtrado de ruido.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .. import config
from ..models import DirectoryHit


@dataclass
class FuzzRun:
    results: list[dict]
    truncated: bool = False
    retried_with_fewer_threads: bool = False
    rate_limit_hits_first_pass: int = 0


def run_ffuf(base_url: str, threads: int = config.FFUF_THREADS_DEFAULT,
             wordlist: str = config.WORDLIST_DEFAULT,
             max_seconds: int = config.FFUF_MAX_SECONDS) -> FuzzRun:
    if not Path(wordlist).is_file():
        raise FileNotFoundError(f"Wordlist no encontrada: {wordlist}")

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = Path(tmp.name)

    truncated = False
    data: dict = {}
    try:
        try:
            subprocess.run(
                [
                    "ffuf", "-ic", "-ac", "-s",
                    "-w", wordlist, "-t", str(threads),
                    "-maxtime", str(max_seconds),
                    "-u", f"{base_url}/FUZZ",
                    "-o", str(tmp_path), "-of", "json",
                ],
                capture_output=True, timeout=max_seconds + 30,
            )
        except FileNotFoundError:
            raise FileNotFoundError("ffuf no está en el PATH")
        except subprocess.TimeoutExpired:
            truncated = True

        if not tmp_path.exists() or tmp_path.stat().st_size == 0:
            return FuzzRun(results=[], truncated=truncated)

        try:
            data = json.loads(tmp_path.read_text())
        except json.JSONDecodeError:
            return FuzzRun(results=[], truncated=truncated)
    finally:
        tmp_path.unlink(missing_ok=True)

    return FuzzRun(results=data.get("results", []), truncated=truncated)


def count_rate_limit_hits(results: list[dict]) -> int:
    return sum(1 for r in results if r.get("status") in config.RATE_LIMIT_STATUS_CODES)


def fuzz(base_url: str, wordlist: str = config.WORDLIST_DEFAULT,
         max_seconds: int = config.FFUF_MAX_SECONDS) -> FuzzRun:
    """Punto de entrada: un barrido y, si el servidor limita, uno más
    con menos hilos. No reintenta si ya se agotó el tiempo ni si no
    hubo ninguna señal de rate-limit.

    `wordlist` y `max_seconds` los decide el caller según el modo:
    common.txt (~4700 líneas) y 120s por defecto; big.txt (~20k) y
    300s bajo --deep, donde sí tiene sentido pagar el tiempo extra.

    OJO: el reintento vuelve a mandar la wordlist COMPLETA a 20 hilos —
    si el servidor ya estaba limitando, esto duplica la carga total en
    vez de aliviarla. Es un trade-off aceptado (mejor resultados parciales
    con más presión que resultados vacíos), pero si ves rate-limit en el
    primer pase, considera bajar FFUF_THREADS_DEFAULT en vez de confiar
    en que el reintento lo arregle por sí solo.
    """
    run = run_ffuf(base_url, threads=config.FFUF_THREADS_DEFAULT,
                    wordlist=wordlist, max_seconds=max_seconds)
    rate_limit_hits = count_rate_limit_hits(run.results)
    run.rate_limit_hits_first_pass = rate_limit_hits

    if run.truncated:
        return run
    if rate_limit_hits <= config.RATE_LIMIT_THRESHOLD:
        return run

    throttled = run_ffuf(base_url, threads=config.FFUF_THREADS_THROTTLED,
                          wordlist=wordlist, max_seconds=max_seconds)
    return FuzzRun(
        results=throttled.results, truncated=throttled.truncated,
        retried_with_fewer_threads=True, rate_limit_hits_first_pass=rate_limit_hits,
    )


def classify_results(results: list[dict]) -> tuple[list[DirectoryHit], list[DirectoryHit], list[str]]:
    """Devuelve (limpios, sospechosos, urls_con_403)."""
    non_redirect = [r for r in results if not (300 <= r.get("status", 0) < 400)]
    pattern_counts = Counter(
        (r.get("status", 0), r.get("words", 0), r.get("lines", 0))
        for r in non_redirect
    )

    clean: list[DirectoryHit] = []
    suspicious: list[DirectoryHit] = []
    forbidden_urls: list[str] = []

    for r in results:
        status, words, lines = r.get("status", 0), r.get("words", 0), r.get("lines", 0)
        hit = DirectoryHit(url=r.get("url", ""), status=status, words=words, lines=lines)

        if status == 403:
            forbidden_urls.append(hit.url)

        if 300 <= status < 400:
            clean.append(hit)
            continue

        if pattern_counts[(status, words, lines)] > config.NOISE_THRESHOLD:
            hit.is_noise_pattern = True
            suspicious.append(hit)
        else:
            clean.append(hit)

    return clean, suspicious, forbidden_urls
