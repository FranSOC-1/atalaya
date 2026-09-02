"""Recoleccion de la superficie de persistencia de Windows.

Todo lo que puede ejecutarse solo, sin que el usuario haga doble clic:
registro, carpetas de inicio, servicios, drivers, tareas programadas y WMI.
"""

from __future__ import annotations

import os
import winreg

from nucleo.modelos import Artefacto
from nucleo.util import expandir, ps_json, resolver_ejecutable

# --------------------------------------------------------------------------- #
# Registro
# --------------------------------------------------------------------------- #

HKLM = winreg.HKEY_LOCAL_MACHINE
HKCU = winreg.HKEY_CURRENT_USER

# (raiz, subclave, etiqueta, vista_64)
CLAVES_AUTOARRANQUE = [
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Registro Run (HKLM)", True),
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "Registro RunOnce (HKLM)", True),
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Registro Run (HKLM 32b)", False),
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "Registro RunOnce (HKLM 32b)", False),
    (HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Registro Run (HKCU)", True),
    (HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "Registro RunOnce (HKCU)", True),
    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "Politica Run (HKLM)", True),
    (HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "Politica Run (HKCU)", True),
]

# Claves donde el VALOR concreto es la carga util, no la clave entera.
VALORES_CRITICOS = [
    (HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", ["Shell", "Userinit", "Taskman", "AppSetup"], "Winlogon"),
    (HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", ["AppInit_DLLs", "LoadAppInit_DLLs"], "AppInit_DLLs"),
    (HKLM, r"SYSTEM\CurrentControlSet\Control\Session Manager", ["BootExecute", "AppCertDlls"], "Session Manager"),
    (HKCU, r"Environment", ["UserInitMprLogonScript"], "Script de logon"),
]


def _abrir(raiz, subclave: str, vista64: bool = True):
    acceso = winreg.KEY_READ | (winreg.KEY_WOW64_64KEY if vista64 else winreg.KEY_WOW64_32KEY)
    return winreg.OpenKey(raiz, subclave, 0, acceso)


def _valores(clave):
    i = 0
    while True:
        try:
            yield winreg.EnumValue(clave, i)
        except OSError:
            return
        i += 1


def _subclaves(clave):
    i = 0
    while True:
        try:
            yield winreg.EnumKey(clave, i)
        except OSError:
            return
        i += 1


def recolectar_registro(avisos: list) -> list[Artefacto]:
    hallados: list[Artefacto] = []

    for raiz, subclave, etiqueta, vista64 in CLAVES_AUTOARRANQUE:
        try:
            with _abrir(raiz, subclave, vista64) as k:
                for nombre, dato, tipo in _valores(k):
                    if tipo not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) or not str(dato).strip():
                        continue
                    hallados.append(Artefacto(
                        origen=etiqueta,
                        nombre=nombre,
                        comando=str(dato),
                        ruta=resolver_ejecutable(str(dato)),
                        detalle={"clave": subclave},
                    ))
        except OSError:
            continue

    for raiz, subclave, nombres, etiqueta in VALORES_CRITICOS:
        try:
            with _abrir(raiz, subclave) as k:
                for nombre in nombres:
                    try:
                        dato, _ = winreg.QueryValueEx(k, nombre)
                    except OSError:
                        continue
                    if isinstance(dato, (list, tuple)):
                        dato = " ".join(str(x) for x in dato)
                    dato = str(dato).strip()
                    if not dato or dato == "0":
                        continue
                    hallados.append(Artefacto(
                        origen=f"{etiqueta} ({nombre})",
                        nombre=nombre,
                        comando=dato,
                        ruta=resolver_ejecutable(dato),
                        detalle={"clave": subclave, "esperado_por_defecto": _valor_por_defecto(nombre)},
                    ))
        except OSError:
            continue

    hallados += _recolectar_ifeo(avisos)
    hallados += _recolectar_bho(avisos)
    return hallados


# Valores legitimos de fabrica: permiten detectar secuestro por comparacion.
_POR_DEFECTO = {
    "Shell": "explorer.exe",
    "Userinit": r"C:\Windows\system32\userinit.exe,",
    "BootExecute": "autocheck autochk *",
}


def _valor_por_defecto(nombre: str) -> str | None:
    return _POR_DEFECTO.get(nombre)


def _recolectar_ifeo(avisos: list) -> list[Artefacto]:
    """Image File Execution Options: un 'Debugger' aqui secuestra un binario entero."""
    hallados = []
    ruta = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    try:
        with _abrir(HKLM, ruta) as k:
            for sub in _subclaves(k):
                try:
                    with _abrir(HKLM, f"{ruta}\\{sub}") as sk:
                        for valor in ("Debugger", "GlobalFlag", "VerifierDlls"):
                            try:
                                dato, _ = winreg.QueryValueEx(sk, valor)
                            except OSError:
                                continue
                            if valor == "GlobalFlag":
                                continue
                            dato = str(dato).strip()
                            if not dato:
                                continue
                            hallados.append(Artefacto(
                                origen=f"IFEO {valor}",
                                nombre=sub,
                                comando=dato,
                                ruta=resolver_ejecutable(dato),
                                detalle={"binario_secuestrado": sub},
                            ))
                except OSError:
                    continue
    except OSError:
        avisos.append("No se pudo leer Image File Execution Options.")
    return hallados


def _recolectar_bho(avisos: list) -> list[Artefacto]:
    """Browser Helper Objects (Internet Explorer / componentes heredados)."""
    hallados = []
    base = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"
    try:
        with _abrir(HKLM, base) as k:
            clsids = list(_subclaves(k))
    except OSError:
        return hallados

    for clsid in clsids:
        dll = None
        try:
            with _abrir(HKLM, rf"SOFTWARE\Classes\CLSID\{clsid}\InprocServer32") as sk:
                dll, _ = winreg.QueryValueEx(sk, "")
        except OSError:
            pass
        if not dll:
            continue
        hallados.append(Artefacto(
            origen="Browser Helper Object",
            nombre=clsid,
            comando=str(dll),
            ruta=resolver_ejecutable(str(dll)),
            detalle={"clsid": clsid},
        ))
    return hallados


# --------------------------------------------------------------------------- #
# Carpetas de inicio
# --------------------------------------------------------------------------- #

def recolectar_carpetas_inicio(avisos: list) -> list[Artefacto]:
    carpetas = [
        (os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"), "Inicio (usuario)"),
        (os.path.join(os.environ.get("ProgramData", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"), "Inicio (todos)"),
    ]
    hallados = []
    for carpeta, etiqueta in carpetas:
        if not carpeta or not os.path.isdir(carpeta):
            continue
        try:
            entradas = os.listdir(carpeta)
        except OSError:
            avisos.append(f"No se pudo listar {carpeta}")
            continue
        for entrada in entradas:
            if entrada.lower() == "desktop.ini":
                continue
            completa = os.path.join(carpeta, entrada)
            destino = _destino_de_acceso_directo(completa) if entrada.lower().endswith(".lnk") else completa
            hallados.append(Artefacto(
                origen=etiqueta,
                nombre=entrada,
                comando=destino or completa,
                ruta=resolver_ejecutable(destino or completa),
                detalle={"contenedor": carpeta, "es_acceso_directo": entrada.lower().endswith(".lnk")},
            ))
    return hallados


def _destino_de_acceso_directo(lnk: str) -> str | None:
    """Resuelve un .lnk usando el Shell COM via PowerShell."""
    ruta_ps = lnk.replace("'", "''")
    datos = ps_json(
        f"$s=New-Object -ComObject WScript.Shell\n"
        f"$a=$s.CreateShortcut('{ruta_ps}')\n"
        f"[pscustomobject]@{{ Destino=$a.TargetPath; Args=$a.Arguments }} | ConvertTo-Json -Compress"
    )
    if not datos:
        return None
    destino = (datos[0].get("Destino") or "").strip()
    args = (datos[0].get("Args") or "").strip()
    if not destino:
        return None
    return f'"{destino}" {args}'.strip()


# --------------------------------------------------------------------------- #
# Servicios y drivers
# --------------------------------------------------------------------------- #

TIPOS_SERVICIO = {1: "driver kernel", 2: "driver sistema", 16: "servicio propio", 32: "servicio compartido"}
ARRANQUE = {0: "boot", 1: "system", 2: "automatico", 3: "manual", 4: "desactivado"}


def recolectar_servicios(avisos: list) -> list[Artefacto]:
    base = r"SYSTEM\CurrentControlSet\Services"
    hallados = []
    try:
        with _abrir(HKLM, base) as k:
            nombres = list(_subclaves(k))
    except OSError:
        avisos.append("No se pudo enumerar los servicios.")
        return hallados

    for nombre in nombres:
        try:
            with _abrir(HKLM, f"{base}\\{nombre}") as sk:
                try:
                    imagen, _ = winreg.QueryValueEx(sk, "ImagePath")
                except OSError:
                    continue
                inicio = _leer_int(sk, "Start")
                tipo = _leer_int(sk, "Type")
                mostrar = _leer_str(sk, "DisplayName") or nombre
        except OSError:
            continue

        imagen = str(imagen).strip()
        if not imagen or inicio == 4:  # ignoramos los desactivados
            continue

        hallados.append(Artefacto(
            origen="Servicio" if (tipo or 0) >= 16 else "Driver",
            nombre=nombre,
            comando=imagen,
            ruta=resolver_ejecutable(imagen),
            detalle={
                "nombre_visible": mostrar,
                "arranque": ARRANQUE.get(inicio, str(inicio)),
                "tipo": TIPOS_SERVICIO.get(tipo, str(tipo)),
            },
        ))
    return hallados


def _leer_int(clave, nombre) -> int | None:
    try:
        v, _ = winreg.QueryValueEx(clave, nombre)
        return int(v)
    except (OSError, ValueError, TypeError):
        return None


def _leer_str(clave, nombre) -> str | None:
    try:
        v, _ = winreg.QueryValueEx(clave, nombre)
        return str(v)
    except OSError:
        return None


# --------------------------------------------------------------------------- #
# Tareas programadas
# --------------------------------------------------------------------------- #

PS_TAREAS = """
$r = @()
foreach ($t in (Get-ScheduledTask)) {
  foreach ($a in $t.Actions) {
    if ($a.Execute) {
      $r += [pscustomobject]@{
        Nombre  = $t.TaskName
        Ruta    = $t.TaskPath
        Estado  = [string]$t.State
        Autor   = [string]$t.Author
        Exe     = [string]$a.Execute
        Args    = [string]$a.Arguments
        Usuario = [string]$t.Principal.UserId
      }
    }
  }
}
$r | ConvertTo-Json -Depth 3 -Compress
"""


def recolectar_tareas(avisos: list) -> list[Artefacto]:
    filas = ps_json(PS_TAREAS)
    if not filas:
        avisos.append("No se obtuvieron tareas programadas (puede requerir permisos).")
        return []

    hallados = []
    for f in filas:
        exe = (f.get("Exe") or "").strip()
        if not exe:
            continue
        args = (f.get("Args") or "").strip()
        comando = f'"{exe}" {args}'.strip() if " " in exe and not exe.startswith('"') else f"{exe} {args}".strip()
        if (f.get("Estado") or "").lower() == "disabled":
            continue
        hallados.append(Artefacto(
            origen="Tarea programada",
            nombre=(f.get("Ruta") or "\\") + (f.get("Nombre") or ""),
            comando=comando,
            ruta=resolver_ejecutable(exe if not args else comando),
            detalle={
                "estado": f.get("Estado"),
                "autor": f.get("Autor"),
                "usuario": f.get("Usuario"),
            },
        ))
    return hallados


# --------------------------------------------------------------------------- #
# Suscripciones WMI (persistencia sin fichero, favorita de APTs)
# --------------------------------------------------------------------------- #

PS_WMI = """
$r = @()
foreach ($c in @('__EventFilter','CommandLineEventConsumer','ActiveScriptEventConsumer','__FilterToConsumerBinding')) {
  try {
    Get-CimInstance -Namespace 'root/subscription' -ClassName $c -ErrorAction Stop | ForEach-Object {
      $r += [pscustomobject]@{
        Clase   = $c
        Nombre  = [string]$_.Name
        Query   = [string]$_.Query
        Comando = [string]$_.CommandLineTemplate
        Script  = [string]$_.ScriptText
      }
    }
  } catch {}
}
$r | ConvertTo-Json -Depth 3 -Compress
"""


def recolectar_wmi(avisos: list) -> list[Artefacto]:
    filas = ps_json(PS_WMI)
    hallados = []
    for f in filas:
        carga = (f.get("Comando") or f.get("Script") or f.get("Query") or "").strip()
        if not carga:
            continue
        hallados.append(Artefacto(
            origen=f"WMI {f.get('Clase')}",
            nombre=f.get("Nombre") or "(sin nombre)",
            comando=carga,
            ruta=resolver_ejecutable(carga) if f.get("Comando") else None,
            detalle={"clase": f.get("Clase"), "query": f.get("Query")},
        ))
    return hallados


# --------------------------------------------------------------------------- #
# Procesos vivos
# --------------------------------------------------------------------------- #

PS_PROCESOS = """
Get-CimInstance Win32_Process |
  Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine |
  ConvertTo-Json -Depth 2 -Compress
"""


def recolectar_procesos(avisos: list) -> list[Artefacto]:
    filas = ps_json(PS_PROCESOS)
    if not filas:
        avisos.append("No se pudo enumerar los procesos.")
        return []

    hallados = []
    for f in filas:
        ruta = (f.get("ExecutablePath") or "").strip()
        nombre = (f.get("Name") or "").strip()
        if not ruta:
            continue  # procesos protegidos del sistema: sin ruta accesible
        hallados.append(Artefacto(
            origen="Proceso vivo",
            nombre=nombre,
            comando=(f.get("CommandLine") or ruta).strip(),
            ruta=expandir(ruta),
            detalle={"pid": f.get("ProcessId"), "padre": f.get("ParentProcessId")},
        ))
    return hallados
