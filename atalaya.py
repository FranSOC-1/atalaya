#!/usr/bin/env python3
"""Atalaya - auditoria de la superficie de ejecucion de Windows.

Enumera todo lo que puede ejecutarse solo en esta maquina (registro, servicios,
drivers, tareas programadas, WMI, carpetas de inicio y procesos vivos), analiza
cada binario y emite un informe priorizado.

Uso:
    python atalaya.py
    python atalaya.py --sin-procesos --salida C:\\informes\\equipo.html
    python atalaya.py --json informe.json --rapido
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import platform
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analizadores import firma as mod_firma
from analizadores import pe as mod_pe
from analizadores.yara_motor import Motor as MotorYara
from colectores import persistencia
from informe import html as informe_html
from nucleo.modelos import ETIQUETA, Informe, Nivel
from nucleo.util import es_admin, sha256_fichero, tamano
from reglas.heuristicas import evaluar

RAIZ = os.path.dirname(os.path.abspath(__file__))

COLOR = {
    Nivel.CRITICO: "\033[91m",
    Nivel.SOSPECHOSO: "\033[93m",
    Nivel.AVISO: "\033[33m",
    Nivel.INFO: "\033[90m",
    Nivel.LIMPIO: "\033[92m",
}
FIN = "\033[0m"


def recolectar(incluir_procesos: bool, avisos: list) -> list:
    fases = [
        ("registro", persistencia.recolectar_registro),
        ("carpetas de inicio", persistencia.recolectar_carpetas_inicio),
        ("servicios y drivers", persistencia.recolectar_servicios),
        ("tareas programadas", persistencia.recolectar_tareas),
        ("suscripciones WMI", persistencia.recolectar_wmi),
    ]
    if incluir_procesos:
        fases.append(("procesos vivos", persistencia.recolectar_procesos))

    artefactos = []
    for etiqueta, fn in fases:
        print(f"  · {etiqueta:<24}", end="", flush=True)
        inicio = time.time()
        try:
            hallados = fn(avisos)
        except Exception as e:
            avisos.append(f"Fallo recolectando {etiqueta}: {e}")
            hallados = []
        print(f"{len(hallados):>5} entradas   ({time.time() - inicio:.1f}s)")
        artefactos.extend(hallados)

    return deduplicar(artefactos)


def deduplicar(artefactos: list) -> list:
    """Colapsa entradas repetidas.

    Para la persistencia basta la clave exacta. Los procesos vivos se agrupan
    ademas por ejecutable: treinta pestanas de Chrome son un unico binario que
    auditar, no treinta hallazgos identicos que sepultan el informe.
    """
    vistos: dict[str, object] = {}
    salida = []
    for a in artefactos:
        if a.origen == "Proceso vivo" and a.ruta:
            clave = "proc|" + a.ruta.lower()
        else:
            clave = a.clave
        previo = vistos.get(clave)
        if previo is not None:
            previo.detalle["instancias"] = previo.detalle.get("instancias", 1) + 1
            continue
        if a.origen == "Proceso vivo":
            a.detalle["instancias"] = 1
        vistos[clave] = a
        salida.append(a)
    return salida


def enriquecer(artefactos: list, rapido: bool, motor_yara, avisos: list) -> None:
    for a in artefactos:
        if a.ruta and os.path.isfile(a.ruta):
            a.existe = True
            a.tamano = tamano(a.ruta)

    if rapido:
        return

    rutas = sorted({a.ruta for a in artefactos if a.existe and a.ruta})
    print(f"  · ficheros unicos           {len(rutas):>5}")

    print("  · firmas Authenticode       ", end="", flush=True)
    inicio = time.time()
    firmas = mod_firma.verificar(rutas)
    print(f"{len(firmas):>5} verificadas ({time.time() - inicio:.1f}s)")

    print("  · analisis PE + hash        ", end="", flush=True)
    inicio = time.time()
    cache_pe: dict[str, dict | None] = {}
    cache_hash: dict[str, str | None] = {}
    for ruta in rutas:
        cache_pe[ruta.lower()] = mod_pe.analizar(ruta)
        cache_hash[ruta.lower()] = sha256_fichero(ruta)
    analizados = sum(1 for v in cache_pe.values() if v)
    print(f"{analizados:>5} binarios PE ({time.time() - inicio:.1f}s)")

    cache_yara: dict[str, list] = {}
    if motor_yara and motor_yara.activo:
        print("  · reglas YARA               ", end="", flush=True)
        inicio = time.time()
        for ruta in rutas:
            cache_yara[ruta.lower()] = motor_yara.escanear(ruta)
        golpes = sum(1 for v in cache_yara.values() if v)
        print(f"{golpes:>5} coincidencias ({time.time() - inicio:.1f}s)")

    for a in artefactos:
        if not a.existe or not a.ruta:
            continue
        k = a.ruta.lower()
        a.firma = firmas.get(k)
        a.pe = cache_pe.get(k)
        a.sha256 = cache_hash.get(k)
        a.yara = cache_yara.get(k, [])


def imprimir_resumen(inf: Informe, limite: int) -> None:
    resumen = inf.resumen()
    print()
    print("  " + "  ".join(
        f"{COLOR[n]}{resumen[ETIQUETA[n]]:>4} {ETIQUETA[n]}{FIN}"
        for n in (Nivel.CRITICO, Nivel.SOSPECHOSO, Nivel.AVISO, Nivel.INFO, Nivel.LIMPIO)
    ))
    print()

    destacados = [a for a in inf.artefactos if a.nivel >= Nivel.AVISO][:limite]
    if not destacados:
        print("  Sin hallazgos por encima del umbral informativo.")
        return

    for a in destacados:
        print(f"  {COLOR[a.nivel]}[{a.puntos:>3}] {ETIQUETA[a.nivel]:<11}{FIN} "
              f"{a.origen} · {a.nombre}")
        print(f"        {(a.ruta or a.comando)[:110]}")
        for s in sorted(a.senales, key=lambda x: -x.puntos)[:3]:
            if s.puntos > 0:
                print(f"        · {s.titulo}")
        print()

    restantes = len([a for a in inf.artefactos if a.nivel >= Nivel.AVISO]) - len(destacados)
    if restantes > 0:
        print(f"  ... y {restantes} mas. Consulta el informe HTML.")


def main() -> int:
    p = argparse.ArgumentParser(
        prog="atalaya",
        description="Audita que se ejecuta en esta maquina Windows y por que.",
    )
    p.add_argument("--salida", default=os.path.join(RAIZ, "informe.html"),
                   help="ruta del informe HTML")
    p.add_argument("--json", dest="json_salida", help="volcado JSON adicional")
    p.add_argument("--sin-procesos", action="store_true",
                   help="no enumerar procesos vivos (escaneo mas rapido)")
    p.add_argument("--rapido", action="store_true",
                   help="solo inventario: sin firmas, PE, hash ni YARA")
    p.add_argument("--yara", default=os.path.join(RAIZ, "reglas", "atalaya.yar"),
                   help="fichero de reglas YARA")
    p.add_argument("--sin-yara", action="store_true", help="desactivar YARA")
    p.add_argument("--top", type=int, default=15, help="hallazgos a mostrar en consola")
    args = p.parse_args()

    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    if platform.system() != "Windows":
        print("Atalaya solo funciona sobre Windows.", file=sys.stderr)
        return 2

    admin = es_admin()
    inicio = time.time()
    avisos: list[str] = []
    if not admin:
        avisos.append("Ejecutado sin privilegios de administrador: las suscripciones WMI, "
                      "algunas tareas programadas y ciertos procesos del sistema quedan fuera "
                      "del alcance. Para una auditoria completa, abre la consola como administrador.")

    print()
    print("  ATALAYA · auditoria de la superficie de ejecucion")
    print(f"  {platform.node()} · {'administrador' if admin else 'usuario limitado'}")
    print()
    print("  Recolectando")

    artefactos = recolectar(not args.sin_procesos, avisos)

    motor = None
    if not args.sin_yara and not args.rapido:
        motor = MotorYara(args.yara)
        if not motor.activo and motor.error:
            avisos.append(f"YARA desactivado: {motor.error}")

    print()
    print("  Analizando")
    enriquecer(artefactos, args.rapido, motor, avisos)

    print("  · aplicando heuristicas     ", end="", flush=True)
    t0 = time.time()
    for a in artefactos:
        evaluar(a)
    print(f"{len(artefactos):>5} evaluados   ({time.time() - t0:.1f}s)")

    inf = Informe(
        maquina=platform.node(),
        usuario=os.environ.get("USERNAME", "?"),
        fecha=dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
        admin=admin,
        duracion=time.time() - inicio,
        artefactos=sorted(artefactos, key=lambda a: (-a.puntos, a.origen, a.nombre)),
        avisos=avisos,
    )

    imprimir_resumen(inf, args.top)

    ruta_informe = informe_html.generar(inf, args.salida)
    print(f"\n  Informe HTML: {ruta_informe}")

    if args.json_salida:
        import json
        with open(args.json_salida, "w", encoding="utf-8") as f:
            json.dump(inf.a_dict(), f, ensure_ascii=False, indent=2)
        print(f"  Volcado JSON: {args.json_salida}")

    print(f"  Completado en {inf.duracion:.1f}s\n")

    criticos = sum(1 for a in artefactos if a.nivel == Nivel.CRITICO)
    return 1 if criticos else 0


if __name__ == "__main__":
    sys.exit(main())
