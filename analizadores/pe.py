"""Analizador de ejecutables PE (Portable Executable) sin dependencias externas.

Extrae cabeceras, secciones con su entropia y la tabla de importaciones.
Suficiente para heuristica estatica: empaquetado, inyeccion, keylogging.
"""

from __future__ import annotations

import datetime as _dt
import struct

from nucleo.util import entropia

MAQUINAS = {0x014C: "x86", 0x8664: "x64", 0x01C0: "ARM", 0xAA64: "ARM64", 0x0200: "IA64"}
SUBSISTEMAS = {1: "nativo", 2: "GUI", 3: "consola", 9: "WinCE", 10: "EFI"}

SCN_CODE = 0x00000020
SCN_EXEC = 0x20000000
SCN_WRITE = 0x80000000

SECCIONES_EMPAQUETADOR = {
    "upx0", "upx1", "upx2", ".upx", ".aspack", ".adata", ".themida", ".vmp0", ".vmp1",
    ".petite", ".enigma1", ".enigma2", ".nsp0", ".mpress1", ".mpress2", "pebundle",
    ".taz", ".packed", ".boom", "!epack", ".mackt", ".perplex", ".sforce3",
}

SECCIONES_NORMALES = {
    ".text", ".data", ".rdata", ".idata", ".edata", ".pdata", ".rsrc", ".reloc",
    ".bss", ".tls", ".didat", ".xdata", ".gfids", ".00cfg", ".sxdata", ".detourc",
    ".detourd", ".textbss", ".msvcjmc", "_rdata", ".rodata", ".shared", ".crt",
}

MAX_SECCIONES = 96
MAX_DLLS = 128
MAX_FUNCIONES = 4096


class _Vista:
    """Acceso seguro a los bytes del fichero, con traduccion RVA -> offset."""

    def __init__(self, datos: bytes):
        self.d = datos
        self.secciones: list[dict] = []

    def u16(self, off: int) -> int:
        return struct.unpack_from("<H", self.d, off)[0]

    def u32(self, off: int) -> int:
        return struct.unpack_from("<I", self.d, off)[0]

    def rva_a_offset(self, rva: int) -> int | None:
        for s in self.secciones:
            inicio = s["rva"]
            fin = inicio + max(s["tam_virtual"], s["tam_raw"])
            if inicio <= rva < fin:
                delta = rva - inicio
                if delta >= s["tam_raw"]:
                    return None
                off = s["off_raw"] + delta
                return off if off < len(self.d) else None
        # Algunos binarios referencian datos en la cabecera
        return rva if rva < len(self.d) else None

    def cadena(self, off: int | None, tope: int = 256) -> str:
        if off is None or off < 0 or off >= len(self.d):
            return ""
        fin = self.d.find(b"\x00", off, off + tope)
        if fin < 0:
            fin = min(off + tope, len(self.d))
        return self.d[off:fin].decode("ascii", errors="replace")


def analizar(ruta: str, tope_bytes: int = 64 * 1024 * 1024) -> dict | None:
    """Devuelve un dict con el analisis PE, o None si no es un PE legible."""
    try:
        import os
        if os.path.getsize(ruta) > tope_bytes:
            return {"error": "fichero demasiado grande para analizar"}
        with open(ruta, "rb") as f:
            datos = f.read()
    except OSError:
        return None

    if len(datos) < 0x40 or datos[:2] != b"MZ":
        return None

    v = _Vista(datos)
    try:
        e_lfanew = v.u32(0x3C)
        if e_lfanew <= 0 or e_lfanew + 24 > len(datos) or datos[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None

        coff = e_lfanew + 4
        maquina = v.u16(coff)
        n_secciones = v.u16(coff + 2)
        timestamp = v.u32(coff + 4)
        tam_opt = v.u16(coff + 16)
        caracteristicas = v.u16(coff + 18)

        opt = coff + 20
        magic = v.u16(opt)
        es_64 = magic == 0x20B

        info: dict = {
            "maquina": MAQUINAS.get(maquina, hex(maquina)),
            "es_dll": bool(caracteristicas & 0x2000),
            "compilado": _fecha(timestamp),
            "compilado_epoch": timestamp,
            "punto_entrada": v.u32(opt + 16),
        }

        if es_64:
            info["subsistema"] = SUBSISTEMAS.get(v.u16(opt + 68), str(v.u16(opt + 68)))
            dll_carac = v.u16(opt + 70)
            n_dirs = v.u32(opt + 108)
            base_dirs = opt + 112
        else:
            info["subsistema"] = SUBSISTEMAS.get(v.u16(opt + 68), str(v.u16(opt + 68)))
            dll_carac = v.u16(opt + 70)
            n_dirs = v.u32(opt + 92)
            base_dirs = opt + 96

        info["aslr"] = bool(dll_carac & 0x0040)
        info["dep"] = bool(dll_carac & 0x0100)
        info["cfg"] = bool(dll_carac & 0x4000)

        directorios = []
        for i in range(min(n_dirs, 16)):
            off = base_dirs + i * 8
            if off + 8 > len(datos):
                break
            directorios.append((v.u32(off), v.u32(off + 4)))

        info["firma_incrustada"] = bool(len(directorios) > 4 and directorios[4][1] > 0)

        # Secciones
        base_sec = e_lfanew + 24 + tam_opt
        secciones = []
        for i in range(min(n_secciones, MAX_SECCIONES)):
            off = base_sec + i * 40
            if off + 40 > len(datos):
                break
            nombre = datos[off:off + 8].rstrip(b"\x00").decode("ascii", errors="replace")
            s = {
                "nombre": nombre,
                "tam_virtual": v.u32(off + 8),
                "rva": v.u32(off + 12),
                "tam_raw": v.u32(off + 16),
                "off_raw": v.u32(off + 20),
                "caracteristicas": v.u32(off + 36),
            }
            crudo = datos[s["off_raw"]:s["off_raw"] + min(s["tam_raw"], 4 * 1024 * 1024)]
            s["entropia"] = round(entropia(crudo), 2)
            s["ejecutable"] = bool(s["caracteristicas"] & (SCN_EXEC | SCN_CODE))
            s["escribible"] = bool(s["caracteristicas"] & SCN_WRITE)
            secciones.append(s)

        v.secciones = secciones
        info["secciones"] = [
            {k: s[k] for k in ("nombre", "entropia", "tam_virtual", "tam_raw", "ejecutable", "escribible")}
            for s in secciones
        ]

        nombres = {s["nombre"].lower() for s in secciones}
        info["seccion_empaquetador"] = sorted(nombres & SECCIONES_EMPAQUETADOR)
        info["secciones_raras"] = sorted(
            n for n in nombres
            if n and n not in SECCIONES_NORMALES and n not in SECCIONES_EMPAQUETADOR
        )
        ejecutables = [s for s in secciones if s["ejecutable"] and s["tam_raw"] > 0]
        info["entropia_max_ejecutable"] = max((s["entropia"] for s in ejecutables), default=0.0)
        info["seccion_ejecutable_escribible"] = [
            s["nombre"] for s in secciones if s["ejecutable"] and s["escribible"]
        ]

        # Importaciones
        imports = _leer_imports(v, directorios, es_64)
        info["imports"] = imports
        info["total_funciones"] = sum(len(fs) for fs in imports.values())
        info["funciones_planas"] = sorted({f.lower() for fs in imports.values() for f in fs})

        return info
    except (struct.error, IndexError, ValueError, MemoryError) as e:
        return {"error": f"PE malformado: {type(e).__name__}"}


def _leer_imports(v: _Vista, directorios: list, es_64: bool) -> dict[str, list[str]]:
    if len(directorios) < 2 or directorios[1][0] == 0:
        return {}

    base = v.rva_a_offset(directorios[1][0])
    if base is None:
        return {}

    resultado: dict[str, list[str]] = {}
    total = 0
    ancho = 8 if es_64 else 4
    marca_ordinal = 0x8000000000000000 if es_64 else 0x80000000

    for i in range(MAX_DLLS):
        off = base + i * 20
        if off + 20 > len(v.d):
            break
        try:
            oft, _, _, rva_nombre, ft = struct.unpack_from("<IIIII", v.d, off)
        except struct.error:
            break
        if oft == 0 and rva_nombre == 0 and ft == 0:
            break

        dll = v.cadena(v.rva_a_offset(rva_nombre)) or f"(dll #{i})"
        funciones: list[str] = []

        tabla = v.rva_a_offset(oft or ft)
        if tabla is not None:
            for j in range(MAX_FUNCIONES):
                pos = tabla + j * ancho
                if pos + ancho > len(v.d) or total >= MAX_FUNCIONES:
                    break
                valor = struct.unpack_from("<Q" if es_64 else "<I", v.d, pos)[0]
                if valor == 0:
                    break
                if valor & marca_ordinal:
                    funciones.append(f"#ordinal{valor & 0xFFFF}")
                else:
                    nombre = v.cadena(v.rva_a_offset(valor + 2))
                    funciones.append(nombre or f"#rva{valor:x}")
                total += 1

        resultado[dll] = funciones
        if total >= MAX_FUNCIONES:
            break

    return resultado


def _fecha(epoch: int) -> str | None:
    if not epoch or epoch > 0xF0000000:
        return None
    try:
        return _dt.datetime.fromtimestamp(epoch, _dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (OverflowError, OSError, ValueError):
        return None
