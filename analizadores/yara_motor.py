"""Integracion opcional con YARA.

Si yara-python no esta instalado, Atalaya sigue funcionando sin este analizador.
Instalacion: pip install yara-python
"""

from __future__ import annotations

import os

try:
    import yara  # type: ignore
    DISPONIBLE = True
except ImportError:
    yara = None
    DISPONIBLE = False


class Motor:
    def __init__(self, ruta_reglas: str):
        self.reglas = None
        self.error: str | None = None
        if not DISPONIBLE:
            self.error = "yara-python no instalado (pip install yara-python)"
            return
        if not os.path.isfile(ruta_reglas):
            self.error = f"no se encuentra el fichero de reglas {ruta_reglas}"
            return
        try:
            self.reglas = yara.compile(filepath=ruta_reglas)
        except Exception as e:
            self.error = f"error compilando reglas: {e}"

    @property
    def activo(self) -> bool:
        return self.reglas is not None

    def escanear(self, ruta: str, tope_bytes: int = 64 * 1024 * 1024) -> list[dict]:
        if not self.activo:
            return []
        try:
            if os.path.getsize(ruta) > tope_bytes:
                return []
            coincidencias = self.reglas.match(filepath=ruta, timeout=20)
        except Exception:
            return []

        salida = []
        for c in coincidencias:
            meta = getattr(c, "meta", {}) or {}
            salida.append({
                "regla": c.rule,
                "descripcion": meta.get("descripcion", ""),
                "puntos": int(meta.get("puntos", 40)),
                "etiquetas": list(getattr(c, "tags", []) or []),
            })
        return salida
