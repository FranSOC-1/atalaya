"""Motor de heuristicas: convierte evidencia en senales puntuadas.

Cada regla es una funcion que recibe un Artefacto ya enriquecido y devuelve
cero o mas Senal. La puntuacion total decide el nivel. Las reglas de supresion
usan puntos negativos: una firma valida de Microsoft debe poder cancelar el
ruido de una heuristica generica, o el informe se llena de falsos positivos.
"""

from __future__ import annotations

import os
import re
import time

from nucleo.modelos import Artefacto, Senal
from nucleo.util import SYSTEM32, SYSWOW64, WINDIR, carpeta_de_confianza

REGLAS = []


def regla(fn):
    REGLAS.append(fn)
    return fn


# --------------------------------------------------------------------------- #
# Datos de apoyo
# --------------------------------------------------------------------------- #

NOMBRES_SISTEMA = {
    "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "winlogon.exe", "services.exe",
    "explorer.exe", "spoolsv.exe", "taskhostw.exe", "dwm.exe", "conhost.exe", "wininit.exe",
    "rundll32.exe", "ctfmon.exe", "sihost.exe", "fontdrvhost.exe", "audiodg.exe",
}

CARPETAS_SISTEMA = {SYSTEM32.lower(), SYSWOW64.lower(), WINDIR.lower(),
                    os.path.join(WINDIR, "WinSxS").lower()}

PROGRAMDATA = os.environ.get("ProgramData", r"C:\ProgramData").lower()

# Contenedores MSIX/AppX: la firma no esta en cada .exe sino en el paquete
# (AppxSignature.p7x), asi que Get-AuthenticodeSignature devuelve NotSigned
# para binarios perfectamente legitimos de la Microsoft Store.
RAICES_EMPAQUETADAS = (
    r"\program files\windowsapps",
    r"\program files\modifiablewindowsapps",
    r"\program files (x86)\windowsapps",
)


def _clasificar_ubicacion(ruta: str) -> tuple[str, int] | None:
    """Devuelve (etiqueta, puntos) si la ubicacion es anomala para algo que
    arranca solo. El peso sube cuanto mas raro es instalar software ahi."""
    r = ruta.lower()
    padre = os.path.dirname(r)

    if "\\$recycle.bin\\" in r:
        return ("la papelera de reciclaje", 55)
    if "\\appdata\\local\\temp\\" in r:
        return ("AppData\\Local\\Temp", 30)
    if r.startswith(WINDIR.lower() + "\\temp\\"):
        return ("Windows\\Temp", 30)
    if "\\users\\public\\" in r:
        return ("Users\\Public", 30)
    if "\\downloads\\" in r:
        return ("la carpeta de descargas", 25)
    # Solo la raiz: Defender y medio Windows viven en subcarpetas de ProgramData.
    if padre == PROGRAMDATA:
        return ("la raiz de ProgramData", 22)
    if "\\appdata\\roaming\\" in r:
        return ("AppData\\Roaming", 12)
    if "\\appdata\\local\\" in r:
        return ("AppData\\Local", 10)
    return None


def firma_de_paquete(a: Artefacto) -> bool:
    """True si el binario vive dentro de un paquete MSIX/AppX firmado."""
    r = (a.ruta or "").lower()
    return any(raiz in r for raiz in RAICES_EMPAQUETADAS)

APIS_INYECCION = {
    "virtualallocex", "writeprocessmemory", "createremotethread", "ntunmapviewofsection",
    "queueuserapc", "setthreadcontext", "ntwritevirtualmemory", "rtlcreateuserthread",
    "ntcreatethreadex", "mapviewoffile", "resumethread",
}

APIS_VIGILANCIA = {
    "setwindowshookexa", "setwindowshookexw", "getasynckeystate", "getkeyboardstate",
    "attachthreadinput", "getforegroundwindow", "bitblt", "getdc",
}

APIS_EVASION = {
    "isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
    "outputdebugstringa", "getticl", "createtoolhelp32snapshot",
}

# Binarios legitimos de Windows abusados para ejecutar codigo (LOLBins).
# Cada patron declara su tecnica MITRE ATT&CK, que la senal arrastra.
PATRONES_LOLBIN = [
    (re.compile(r"powershell.*\s-e(nc|ncoded|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}", re.I),
     "PowerShell con comando codificado en base64", 45, "T1059.001"),
    (re.compile(r"powershell.*(-w(indowstyle)?\s+hidden|-nop\b|-noni\b|-ep\s+bypass|-executionpolicy\s+bypass)", re.I),
     "PowerShell oculto o saltandose la politica de ejecucion", 30, "T1059.001"),
    (re.compile(r"\bmshta\b.*(http|javascript:|vbscript:)", re.I),
     "mshta ejecutando contenido remoto o script en linea", 45, "T1218.005"),
    (re.compile(r"\brundll32\b.*(javascript:|http)", re.I),
     "rundll32 ejecutando script o URL", 45, "T1218.011"),
    (re.compile(r"\bregsvr32\b.*(/i:\s*http|scrobj\.dll)", re.I),
     "regsvr32 cargando scriptlet remoto (Squiblydoo)", 45, "T1218.010"),
    (re.compile(r"\bcertutil\b.*(-decode|-urlcache|-f\s+-split)", re.I),
     "certutil usado para descargar o decodificar carga util", 40, "T1105"),
    (re.compile(r"\bbitsadmin\b.*(/transfer|/create)", re.I),
     "bitsadmin transfiriendo ficheros", 35, "T1197"),
    (re.compile(r"\bwmic\b.*process.*call\s+create", re.I),
     "wmic creando procesos", 35, "T1047"),
    (re.compile(r"(curl|wget|Invoke-WebRequest|iwr|Invoke-Expression|iex)\b.*http", re.I),
     "descarga y ejecucion desde red en la linea de comandos", 35, "T1105"),
    (re.compile(r"\b(msbuild|installutil|regasm|regsvcs|cmstp|mavinject)\b", re.I),
     "binario del sistema usado habitualmente para evadir listas blancas", 25, "T1127"),
    (re.compile(r"FromBase64String|::FromBase64|\[Convert\]", re.I),
     "decodificacion base64 embebida en el comando", 25, "T1027"),
]

# Suscripciones WMI que Windows trae de serie: no son persistencia hostil.
WMI_DE_FABRICA = {
    "SCM Event Log Filter",
    "SCM Event Log Consumer",
    "BVTFilter",
    "BVTConsumer",
    "TSLogonFilter",
    "TSLogonConsumer",
    "RmAssistEventFilter",
}

DOBLE_EXTENSION = re.compile(
    r"\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt|mp4|zip|rar)\s*\.(exe|scr|com|pif|bat|cmd|vbs|js)$", re.I
)


def _ruta_baja(a: Artefacto) -> str:
    return (a.ruta or "").lower()


def _es_persistencia(a: Artefacto) -> bool:
    return a.origen != "Proceso vivo"


# --------------------------------------------------------------------------- #
# Reglas: firma
# --------------------------------------------------------------------------- #

@regla
def firma_rota(a: Artefacto):
    if not a.firma:
        return []
    estado = a.firma.get("estado")
    if estado == "HashMismatch":
        return [Senal("FIRMA_ALTERADA", "Firma digital no coincide con el fichero",
                      "El binario esta firmado pero su contenido fue modificado despues de firmarlo. "
                      "Es el patron clasico de un ejecutable legitimo troyanizado.", 65)]
    if estado == "NotTrusted":
        return [Senal("FIRMA_NO_CONFIABLE", "Firmado por una entidad no confiable",
                      f"Firmante: {a.firma.get('firmante') or 'desconocido'}. La cadena de certificacion "
                      "no llega a una raiz de confianza del sistema.", 40)]
    return []


@regla
def sin_firma(a: Artefacto):
    if not a.firma or not a.existe:
        return []
    if a.firma.get("estado") != "NotSigned":
        return []
    if firma_de_paquete(a):
        return [Senal("FIRMA_PAQUETE", "Firmado a nivel de paquete (MSIX/AppX)",
                      "Los binarios de la Microsoft Store no llevan Authenticode individual: "
                      "su integridad la garantiza la firma del paquete que los contiene.", 0)]
    if _es_persistencia(a):
        return [Senal("SIN_FIRMA_PERSISTENTE", "Sin firma digital y con persistencia",
                      "Un binario que arranca solo y no esta firmado no puede atribuirse a ningun "
                      "fabricante. No es concluyente, pero eleva la prioridad de revision.", 15)]
    return [Senal("SIN_FIRMA", "Sin firma digital",
                  "El binario no esta firmado.", 5)]


@regla
def firma_confiable(a: Artefacto):
    """Senal informativa. La atenuacion real se aplica en evaluar(), no aqui:
    restar puntos no bastaba (explorer.exe salia critico igualmente)."""
    if not a.firma or not a.firma.get("confiable"):
        return []
    if a.firma.get("es_microsoft"):
        return [Senal("FIRMA_MICROSOFT", "Firma valida de Microsoft",
                      f"Firmado por {a.firma.get('firmante')}. Binario de plataforma: las "
                      "heuristicas de contenido quedan anuladas para este artefacto.", 0)]
    return [Senal("FIRMA_VALIDA", "Firma digital valida",
                  f"Firmado por {a.firma.get('firmante')}, cadena de confianza correcta. "
                  "Las heuristicas de contenido cuentan al 20%.", 0)]


# --------------------------------------------------------------------------- #
# Reglas: ubicacion y nombre
# --------------------------------------------------------------------------- #

@regla
def ruta_volatil(a: Artefacto):
    r = _ruta_baja(a)
    if not r or not _es_persistencia(a):
        return []
    clasificacion = _clasificar_ubicacion(r)
    if not clasificacion:
        return []
    etiqueta, puntos = clasificacion
    return [Senal("RUTA_VOLATIL", f"Se ejecuta desde {etiqueta}",
                  f"Ruta: {a.ruta}. El software instalado normalmente vive en Program Files; "
                  "las carpetas de usuario y temporales son donde se deja caer el malware.",
                  puntos)]


@regla
def suplanta_binario_sistema(a: Artefacto):
    r = _ruta_baja(a)
    if not r:
        return []
    base = os.path.basename(r)
    if base not in NOMBRES_SISTEMA:
        return []
    carpeta = os.path.dirname(r)
    if any(carpeta.startswith(c) for c in CARPETAS_SISTEMA):
        return []
    return [Senal("SUPLANTA_SISTEMA", f"Usa el nombre de un binario del sistema fuera de su sitio",
                  f"'{base}' deberia estar en System32, no en {os.path.dirname(a.ruta or '')}. "
                  "Suplantacion de nombre para pasar desapercibido en el administrador de tareas.", 60)]


@regla
def nombre_enganoso(a: Artefacto):
    senales = []
    objetivo = a.ruta or a.nombre or ""
    base = os.path.basename(objetivo)

    if DOBLE_EXTENSION.search(base):
        senales.append(Senal("DOBLE_EXTENSION", "Doble extension enganosa",
                             f"'{base}' aparenta ser un documento pero es un ejecutable.", 45))

    if any(c in objetivo for c in ("\u202e", "\u202d", "\u200b", "\u2066", "\u2067")):
        senales.append(Senal("CARACTER_INVISIBLE", "Caracteres de control Unicode en el nombre",
                             "Se usan marcas de direccion de texto (RTL override) para invertir "
                             "visualmente la extension del fichero.", 60))

    return senales


@regla
def ruta_sin_comillas(a: Artefacto):
    """Servicio con ruta que tiene espacios y no esta entrecomillada: escalada de privilegios clasica."""
    # Solo aplica a servicios en modo usuario: los drivers los carga el kernel,
    # que no parsea la ruta con las reglas de CreateProcess.
    if a.origen != "Servicio":
        return []
    cmd = a.comando.strip()
    if cmd.startswith('"') or " " not in cmd:
        return []
    primer_token = cmd.split()[0]
    if primer_token.lower().endswith(".exe"):
        return []
    return [Senal("RUTA_SIN_COMILLAS", "Ruta de servicio sin comillas con espacios",
                  f"'{cmd}' permite secuestro por ruta no entrecomillada: un ejecutable colocado en "
                  "un punto intermedio de la ruta se ejecutaria con privilegios del servicio.", 18)]


@regla
def fichero_ausente(a: Artefacto):
    if a.existe or not a.ruta or not _es_persistencia(a):
        return []
    if a.origen.startswith("WMI"):
        return []
    return [Senal("FICHERO_AUSENTE", "La entrada apunta a un fichero que no existe",
                  f"No se encuentra {a.ruta}. Puede ser residuo de una desinstalacion, o de una "
                  "limpieza incompleta que dejo la persistencia viva.", 12)]


# --------------------------------------------------------------------------- #
# Reglas: linea de comandos
# --------------------------------------------------------------------------- #

@regla
def lolbin(a: Artefacto):
    senales = []
    cmd = a.comando or ""
    for patron, descripcion, puntos, tecnica in PATRONES_LOLBIN:
        if patron.search(cmd):
            senales.append(Senal("LOLBIN", descripcion,
                                 f"Comando: {cmd[:400]}", puntos, attack=tecnica))
    return senales


@regla
def secuestro_winlogon(a: Artefacto):
    esperado = a.detalle.get("esperado_por_defecto")
    if not esperado:
        return []
    actual = (a.comando or "").strip().lower().rstrip(",")
    if esperado.lower().rstrip(",") in actual and len(actual) <= len(esperado) + 4:
        return []
    return [Senal("VALOR_CRITICO_MODIFICADO", f"Valor critico del sistema modificado",
                  f"'{a.nombre}' vale «{a.comando}» y de fabrica deberia ser «{esperado}». "
                  "Es un punto de secuestro que se ejecuta antes que el escritorio.", 55)]


@regla
def ifeo_debugger(a: Artefacto):
    if not a.origen.startswith("IFEO Debugger"):
        return []
    return [Senal("IFEO_DEBUGGER", "Secuestro por depurador de imagen (IFEO)",
                  f"Al ejecutar '{a.nombre}' Windows lanzara «{a.comando}» en su lugar. "
                  "Tecnica usada tanto para bloquear antivirus como para persistir.", 60)]


@regla
def wmi_persistente(a: Artefacto):
    if not a.origen.startswith("WMI"):
        return []
    if "FilterToConsumerBinding" in a.origen:
        return []
    if (a.nombre or "").strip() in WMI_DE_FABRICA:
        return []
    return [Senal("WMI_SUSCRIPCION", "Persistencia por suscripcion WMI",
                  f"Clase {a.detalle.get('clase')}. Es un mecanismo sin fichero, invisible para "
                  "los antivirus que solo escanean disco, y raro en instalaciones limpias.", 35)]


# --------------------------------------------------------------------------- #
# Reglas: contenido del binario (PE)
# --------------------------------------------------------------------------- #

@regla
def empaquetado(a: Artefacto):
    pe = a.pe
    if not pe or pe.get("error"):
        return []
    senales = []

    if pe.get("seccion_empaquetador"):
        senales.append(Senal("EMPAQUETADOR", "Empaquetador conocido detectado",
                             f"Secciones: {', '.join(pe['seccion_empaquetador'])}. El codigo real esta "
                             "comprimido y solo aparece en memoria al ejecutarse.", 35, "contenido"))

    ent = pe.get("entropia_max_ejecutable") or 0
    if ent >= 7.2 and not pe.get("seccion_empaquetador"):
        senales.append(Senal("ENTROPIA_ALTA", "Codigo con entropia muy alta",
                             f"Entropia maxima en seccion ejecutable: {ent}/8. Indica contenido "
                             "cifrado o comprimido; legitimo en instaladores, sospechoso en el resto.",
                             22, "contenido"))

    if pe.get("seccion_ejecutable_escribible"):
        senales.append(Senal("SECCION_RWX", "Seccion ejecutable y escribible a la vez",
                             f"Secciones: {', '.join(pe['seccion_ejecutable_escribible'])}. Permite que "
                             "el propio codigo se reescriba en memoria; muy poco habitual en software limpio.",
                             25, "contenido"))

    return senales


@regla
def imports_sospechosos(a: Artefacto):
    pe = a.pe
    if not pe or pe.get("error"):
        return []
    senales = []
    funcs = set(pe.get("funciones_planas") or [])

    inyeccion = sorted(funcs & APIS_INYECCION)
    if len(inyeccion) >= 3:
        senales.append(Senal("API_INYECCION", "Importa el juego completo de APIs de inyeccion",
                             f"Funciones: {', '.join(inyeccion)}. Es la combinacion que se usa para "
                             "escribir y ejecutar codigo dentro de otro proceso.", 40, "contenido"))
    elif len(inyeccion) == 2:
        senales.append(Senal("API_INYECCION_PARCIAL", "Importa APIs de manipulacion de memoria ajena",
                             f"Funciones: {', '.join(inyeccion)}.", 20, "contenido"))

    vigilancia = sorted(funcs & APIS_VIGILANCIA)
    if len(vigilancia) >= 2:
        senales.append(Senal("API_VIGILANCIA", "Importa APIs de captura de teclado o pantalla",
                             f"Funciones: {', '.join(vigilancia)}. Compatible con keylogger o "
                             "software de monitorizacion.", 30, "contenido"))

    evasion = sorted(funcs & APIS_EVASION)
    if len(evasion) >= 2:
        senales.append(Senal("API_ANTIDEPURACION", "Importa APIs de deteccion de depurador",
                             f"Funciones: {', '.join(evasion)}.", 15, "contenido"))

    total = pe.get("total_funciones") or 0
    if total <= 5 and not pe.get("es_dll") and a.existe and (a.tamano or 0) > 20 * 1024:
        senales.append(Senal("IMPORTS_ANEMICOS", "Tabla de importaciones casi vacia",
                             f"Solo {total} funciones importadas en un ejecutable de "
                             f"{(a.tamano or 0) // 1024} KB. Sintoma tipico de codigo empaquetado que "
                             "resuelve sus llamadas en tiempo de ejecucion.", 25, "contenido"))

    return senales


@regla
def cabecera_anomala(a: Artefacto):
    pe = a.pe
    if not pe or pe.get("error"):
        return []
    senales = []

    epoch = pe.get("compilado_epoch") or 0
    ahora = int(time.time())
    # Los compiladores modernos escriben aqui un hash reproducible en vez de una
    # fecha, asi que solo alarma lo absurdamente lejano en el futuro.
    if epoch > ahora + 400 * 86400:
        senales.append(Senal("FECHA_FUTURA", "Fecha de compilacion muy en el futuro",
                             f"Declara {pe.get('compilado')}. Timestamp manipulado.", 20, "contenido"))
    elif 0 < epoch < 788918400:  # anterior a 1995
        senales.append(Senal("FECHA_IMPOSIBLE", "Fecha de compilacion anterior a 1995",
                             f"Declara {pe.get('compilado')}. Timestamp manipulado.", 15, "contenido"))

    if a.existe and not pe.get("aslr") and not pe.get("dep"):
        senales.append(Senal("SIN_MITIGACIONES", "Compilado sin ASLR ni DEP",
                             "Binario moderno sin mitigaciones basicas de explotacion.", 10, "contenido"))

    return senales


@regla
def yara_coincide(a: Artefacto):
    if not a.yara:
        return []
    nombres = ", ".join(m.get("regla", "?") for m in a.yara)
    puntos = max((m.get("puntos", 40) for m in a.yara), default=40)
    return [Senal("YARA", "Coincidencia con regla YARA",
                  f"Reglas activadas: {nombres}.", puntos, "contenido")]


# --------------------------------------------------------------------------- #
# Evaluacion
# --------------------------------------------------------------------------- #

def factor_contenido(a: Artefacto) -> float:
    """Cuanto pesan las heuristicas de contenido segun la firma del binario.

    Un ejecutable firmado y validado por Windows tiene un responsable con
    nombre y apellidos detras. Que importe CreateRemoteThread no dice nada:
    lo hacen Chrome, explorer.exe y todos los antivirus del mercado. Lo que
    si sigue contando es el contexto (donde vive, como arranca).
    """
    f = a.firma or {}
    if not f.get("confiable"):
        return 0.2 if firma_de_paquete(a) else 1.0
    if f.get("es_microsoft"):
        return 0.0
    return 0.2


def evaluar(a: Artefacto) -> Artefacto:
    from nucleo.modelos import nivel_de

    senales: list[Senal] = []
    for fn in REGLAS:
        try:
            senales.extend(fn(a) or [])
        except Exception as e:  # una regla rota no debe tumbar el escaneo
            senales.append(Senal("ERROR_REGLA", f"Fallo en la regla {fn.__name__}", str(e), 0))

    factor = factor_contenido(a)
    contexto = [s for s in senales if s.categoria != "contenido"]
    contenido = [s for s in senales if s.categoria == "contenido"]

    if factor != 1.0:
        for s in contenido:
            s.puntos = int(round(s.puntos * factor))
            s.detalle += (" (anulado: binario de plataforma firmado por Microsoft)"
                          if factor == 0.0 else " (atenuado por firma digital valida)")

    # Con editor identificado, las senales de contenido describen UN perfil de
    # capacidades, no varias pruebas independientes: quien inyecta codigo suele
    # ademas detectar depuradores y traer secciones empaquetadas. Sumarlas
    # inflaba a Chrome, Steam y Spotify hasta nivel aviso. Sin firma valida si
    # acumulan, porque ahi cada senal si aporta evidencia nueva.
    if factor == 1.0:
        suma_contenido = sum(s.puntos for s in contenido)
    else:
        suma_contenido = max((s.puntos for s in contenido), default=0)

    total = sum(s.puntos for s in contexto) + suma_contenido

    a.senales = [s for s in senales if s.puntos != 0 or s.codigo.startswith("FIRMA")]
    a.puntos = max(0, total)
    a.nivel = nivel_de(a.puntos)

    from reglas.attack import tecnicas_de
    a.attack = tecnicas_de(a)
    return a
