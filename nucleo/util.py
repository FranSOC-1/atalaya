"""Utilidades comunes: hashes, entropia, resolucion de rutas y puente con PowerShell."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

WINDIR = os.environ.get("SystemRoot", r"C:\Windows")
SYSTEM32 = os.path.join(WINDIR, "System32")
SYSWOW64 = os.path.join(WINDIR, "SysWOW64")

EXTENSIONES_EJECUTABLES = (
    ".exe", ".dll", ".com", ".scr", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".msi", ".cpl",
)


# --------------------------------------------------------------------------- #
# Hash y entropia
# --------------------------------------------------------------------------- #

def sha256_fichero(ruta: str, tope_bytes: int = 200 * 1024 * 1024) -> str | None:
    """SHA256 del fichero. Devuelve None si no se puede leer o excede el tope."""
    try:
        if os.path.getsize(ruta) > tope_bytes:
            return None
        h = hashlib.sha256()
        with open(ruta, "rb") as f:
            for bloque in iter(lambda: f.read(1024 * 1024), b""):
                h.update(bloque)
        return h.hexdigest()
    except OSError:
        return None


def entropia(datos: bytes) -> float:
    """Entropia de Shannon en bits/byte (0 a 8). >7.2 sugiere cifrado o empaquetado."""
    if not datos:
        return 0.0
    total = len(datos)
    return -sum(
        (c / total) * math.log2(c / total) for c in Counter(datos).values()
    )


# --------------------------------------------------------------------------- #
# Resolucion de rutas
# --------------------------------------------------------------------------- #

_RE_ENV = re.compile(r"%([^%]+)%")


def expandir(texto: str) -> str:
    """Expande %VAR%, quita prefijos NT y normaliza barras."""
    if not texto:
        return ""
    t = texto.strip().strip('"')
    for prefijo in ("\\??\\", "\\SystemRoot\\", "\\\\?\\"):
        if t.lower().startswith(prefijo.lower()):
            resto = t[len(prefijo):]
            t = os.path.join(WINDIR, resto) if "systemroot" in prefijo.lower() else resto
            break
    t = _RE_ENV.sub(lambda m: os.environ.get(m.group(1), m.group(0)), t)
    t = os.path.expandvars(t)
    return t.replace("/", "\\")


def _buscar_en_rutas_sistema(nombre: str) -> str | None:
    if not os.path.splitext(nombre)[1]:
        nombre += ".exe"
    candidatos = [SYSTEM32, SYSWOW64, WINDIR] + os.environ.get("PATH", "").split(os.pathsep)
    for carpeta in candidatos:
        if not carpeta:
            continue
        posible = os.path.join(carpeta, nombre)
        if os.path.isfile(posible):
            return posible
    return None


def resolver_ejecutable(comando: str) -> str | None:
    """Extrae la ruta real del ejecutable a partir de una linea de comandos.

    Maneja comillas, argumentos sin comillas con espacios ("C:\\Program Files\\..."),
    variables de entorno y binarios que viven en System32.
    """
    if not comando or not comando.strip():
        return None

    bruto = comando.strip()

    # Caso 0: la cadena entera ya es un fichero existente (entradas de carpeta
    # de inicio, rutas con espacios sin argumentos detras).
    directo = expandir(bruto)
    if directo and os.path.isfile(directo):
        return directo

    # Caso 1: ejecutable entre comillas
    if bruto.startswith('"'):
        fin = bruto.find('"', 1)
        if fin > 0:
            ruta = expandir(bruto[1:fin])
            return ruta if os.path.isfile(ruta) else (_buscar_en_rutas_sistema(os.path.basename(ruta)) or ruta)

    texto = expandir(bruto)

    # Caso 2: ruta sin comillas con espacios. Probamos prefijos que acaben en
    # extension ejecutable conocida y existan en disco (rundll32 C:\a b.dll,Init).
    minus = texto.lower()
    for ext in EXTENSIONES_EJECUTABLES:
        idx = 0
        while True:
            idx = minus.find(ext, idx)
            if idx < 0:
                break
            corte = idx + len(ext)
            candidato = texto[:corte].strip()
            if os.path.isfile(candidato):
                return candidato
            idx = corte

    # Caso 3: primer token
    token = texto.split()[0] if texto.split() else texto
    token = token.rstrip(",")
    if os.path.isfile(token):
        return token
    encontrado = _buscar_en_rutas_sistema(os.path.basename(token))
    if encontrado:
        return encontrado
    return token if token else None


def carpeta_de_confianza(ruta: str | None) -> bool:
    """True si la ruta esta bajo Windows o Program Files (menor riesgo de base)."""
    if not ruta:
        return False
    r = ruta.lower()
    bases = [
        WINDIR.lower(),
        os.environ.get("ProgramFiles", r"C:\Program Files").lower(),
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)").lower(),
    ]
    return any(r.startswith(b + "\\") for b in bases)


# --------------------------------------------------------------------------- #
# Puente con PowerShell
# --------------------------------------------------------------------------- #

def ps_json(script: str, timeout: int = 180) -> list:
    """Ejecuta un script PowerShell y devuelve su salida JSON como lista.

    Se escribe a fichero temporal en vez de pasarlo por -Command: evita todos los
    problemas de escapado entre el quoting de Windows y el parser de PowerShell.
    """
    cabecera = (
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8\n"
        "$ProgressPreference='SilentlyContinue'\n"
        "$ErrorActionPreference='SilentlyContinue'\n"
    )
    fd, ruta = tempfile.mkstemp(suffix=".ps1", text=False)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write((cabecera + script).encode("utf-8-sig"))
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-File", ruta],
            capture_output=True, timeout=timeout,
        )
        salida = proc.stdout.decode("utf-8", errors="replace").strip()
    except (subprocess.TimeoutExpired, OSError):
        return []
    finally:
        try:
            os.unlink(ruta)
        except OSError:
            pass

    if not salida:
        return []
    try:
        datos = json.loads(salida)
    except json.JSONDecodeError:
        return []
    if datos is None:
        return []
    return datos if isinstance(datos, list) else [datos]


def es_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def leer_cabecera(ruta: str, n: int = 4096) -> bytes:
    try:
        with open(ruta, "rb") as f:
            return f.read(n)
    except OSError:
        return b""


def tamano(ruta: str) -> int | None:
    try:
        return os.path.getsize(ruta)
    except OSError:
        return None
