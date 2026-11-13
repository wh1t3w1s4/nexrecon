"""Export a JSON. Gracias a que ScanResult es un árbol de dataclasses,
esto es literalmente una línea — en bash habría que construir el JSON
a mano con jq o concatenando strings, propenso a errores de escapado.
"""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from ..models import ScanResult


def _default(obj):
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    if hasattr(obj, "value"):  # Enum
        return obj.value
    raise TypeError(f"No serializable: {type(obj)}")


def to_json(result: ScanResult) -> str:
    return json.dumps(dataclasses.asdict(result), default=_default, indent=2, ensure_ascii=False)


def write_json(result: ScanResult, path: Path) -> None:
    path.write_text(to_json(result), encoding="utf-8")
