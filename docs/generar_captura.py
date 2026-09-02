#!/usr/bin/env python3
"""Genera un informe de demostracion para la captura del README.

Usa los casos sinteticos del banco de pruebas (datos ficticios, maquina
"EQUIPO-DEMO"): la captura ensena el informe real sin exponer ningun dato
de una maquina de verdad. Reproducible por cualquiera:

    python docs/generar_captura.py
"""

from __future__ import annotations

import os
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, RAIZ)

from nucleo.modelos import Informe  # noqa: E402
from reglas.heuristicas import evaluar  # noqa: E402
from informe import html as informe_html  # noqa: E402
from pruebas.banco import CASOS  # noqa: E402


def main() -> int:
    artefactos = []
    for _descripcion, art, _nivel in CASOS:
        evaluar(art)
        artefactos.append(art)
    artefactos.sort(key=lambda a: (-a.puntos, a.origen, a.nombre))

    inf = Informe(
        maquina="EQUIPO-DEMO",
        usuario="analista",
        fecha="2026-09-03 10:00",
        admin=True,
        duracion=28.4,
        artefactos=artefactos,
        avisos=[],
    )

    destino = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo-informe.html")
    informe_html.generar(inf, destino)
    resumen = inf.resumen()
    print(f"Informe demo generado: {destino}")
    print(f"Artefactos: {len(artefactos)} | resumen: {resumen}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
