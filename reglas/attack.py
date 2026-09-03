"""Mapeo de la evidencia de Atalaya a técnicas de MITRE ATT&CK.

Dos fuentes de técnica por artefacto:

1. El MECANISMO de persistencia (el `origen` del artefacto). Que algo arranque
   desde una clave Run es T1547.001 aunque el binario sea limpio: la técnica
   describe *cómo* consigue ejecutarse, no si es malicioso.

2. Cada SEÑAL heurística que se dispara (por su código, o por la técnica que la
   propia señal declara en `Senal.attack`, como los LOLBins).

El objetivo es que cada hallazgo cite un ID concreto (Txxxx[.xxx]) con su motivo,
nunca una etiqueta genérica. Donde no existe una técnica ATT&CK limpia, se dice.

Referencia: https://attack.mitre.org/  (matriz Enterprise)
"""

from __future__ import annotations

from nucleo.modelos import Artefacto

# --------------------------------------------------------------------------- #
# Catálogo de técnicas usadas (id -> nombre)
# --------------------------------------------------------------------------- #

TECNICAS: dict[str, str] = {
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    "T1547.004": "Boot or Logon Autostart Execution: Winlogon Helper DLL",
    "T1547.006": "Boot or Logon Autostart Execution: Kernel Modules and Extensions",
    "T1546.003": "Event Triggered Execution: Windows Management Instrumentation Event Subscription",
    "T1546.009": "Event Triggered Execution: AppCert DLLs",
    "T1546.010": "Event Triggered Execution: AppInit DLLs",
    "T1546.012": "Event Triggered Execution: Image File Execution Options Injection",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1037.001": "Boot or Logon Initialization Scripts: Logon Script (Windows)",
    "T1176": "Browser Extensions",
    "T1055": "Process Injection",
    "T1056.001": "Input Capture: Keylogging",
    "T1113": "Screen Capture",
    "T1622": "Debugger Evasion",
    "T1027": "Obfuscated Files or Information",
    "T1027.002": "Obfuscated Files or Information: Software Packing",
    "T1036": "Masquerading",
    "T1036.002": "Masquerading: Right-to-Left Override",
    "T1036.005": "Masquerading: Match Legitimate Name or Location",
    "T1036.007": "Masquerading: Double File Extension",
    "T1574.009": "Hijack Execution Flow: Path Interception by Unquoted Path",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1218.005": "System Binary Proxy Execution: Mshta",
    "T1218.010": "System Binary Proxy Execution: Regsvr32",
    "T1218.011": "System Binary Proxy Execution: Rundll32",
    "T1218": "System Binary Proxy Execution",
    "T1127": "Trusted Developer Utilities Proxy Execution",
    "T1105": "Ingress Tool Transfer",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1197": "BITS Jobs",
    "T1047": "Windows Management Instrumentation",
}


def url(tid: str) -> str:
    base = tid.split(".")
    if len(base) == 2:
        return f"https://attack.mitre.org/techniques/{base[0]}/{base[1]}/"
    return f"https://attack.mitre.org/techniques/{tid}/"


# --------------------------------------------------------------------------- #
# Técnica por MECANISMO de persistencia (el `origen` del artefacto)
# --------------------------------------------------------------------------- #
# Se evalúa por coincidencia de subcadena, en orden: gana la primera que encaje.

POR_ORIGEN: list[tuple[str, str]] = [
    ("Registro Run", "T1547.001"),
    ("Registro RunOnce", "T1547.001"),
    ("Politica Run", "T1547.001"),
    ("Inicio (", "T1547.001"),          # carpetas de inicio
    ("Winlogon", "T1547.004"),
    ("AppInit_DLLs", "T1546.010"),
    ("IFEO", "T1546.012"),
    ("Session Manager (AppCertDlls)", "T1546.009"),
    ("Script de logon", "T1037.001"),
    ("Browser Helper Object", "T1176"),  # legado de Internet Explorer
    ("Driver", "T1547.006"),
    ("Servicio", "T1543.003"),
    ("Tarea programada", "T1053.005"),
    ("WMI", "T1546.003"),
]

# `origen` sin técnica de persistencia asociada (superficie de análisis, no
# mecanismo de arranque). No es un hueco: es que no aplica.
SIN_TECNICA_DE_ORIGEN = {"Proceso vivo", "Session Manager (BootExecute)"}


# --------------------------------------------------------------------------- #
# Técnica por CÓDIGO de señal heurística
# --------------------------------------------------------------------------- #

POR_CODIGO: dict[str, str] = {
    "SUPLANTA_SISTEMA": "T1036.005",
    "DOBLE_EXTENSION": "T1036.007",
    "CARACTER_INVISIBLE": "T1036.002",
    "FIRMA_ALTERADA": "T1036",           # binario firmado y modificado después
    "RUTA_SIN_COMILLAS": "T1574.009",
    "IFEO_DEBUGGER": "T1546.012",
    "VALOR_CRITICO_MODIFICADO": "T1547.004",
    "WMI_SUSCRIPCION": "T1546.003",
    "EMPAQUETADOR": "T1027.002",
    "ENTROPIA_ALTA": "T1027.002",
    "IMPORTS_ANEMICOS": "T1027.002",
    "SECCION_RWX": "T1055",
    "API_INYECCION": "T1055",
    "API_INYECCION_PARCIAL": "T1055",
    "API_VIGILANCIA": "T1056.001",
    "API_ANTIDEPURACION": "T1622",
}


def _motivo_origen(a: Artefacto) -> str:
    return f"Mecanismo de arranque: {a.origen}"


def tecnicas_de(a: Artefacto) -> list[dict]:
    """Devuelve las técnicas ATT&CK del artefacto: la del mecanismo de arranque
    más las de cada señal disparada. Deduplicado, con motivo."""
    encontradas: dict[str, str] = {}  # id -> motivo (primer motivo gana)

    # 1) Por mecanismo de persistencia
    origen = a.origen or ""
    if origen not in SIN_TECNICA_DE_ORIGEN:
        for aguja, tid in POR_ORIGEN:
            if aguja in origen:
                encontradas.setdefault(tid, _motivo_origen(a))
                break

    # 2) Por cada señal con puntos efectivos
    for s in a.senales:
        if s.puntos == 0 and not (s.codigo or "").startswith("FIRMA"):
            continue
        tid = s.attack or POR_CODIGO.get(s.codigo)
        if tid:
            encontradas.setdefault(tid, s.titulo)

    return [
        {"id": tid, "nombre": TECNICAS.get(tid, tid), "url": url(tid), "motivo": motivo}
        for tid, motivo in encontradas.items()
    ]
