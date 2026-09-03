"""Modelos de datos de Atalaya."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import IntEnum


class Nivel(IntEnum):
    LIMPIO = 0
    INFO = 1
    AVISO = 2
    SOSPECHOSO = 3
    CRITICO = 4


ETIQUETA = {
    Nivel.LIMPIO: "limpio",
    Nivel.INFO: "info",
    Nivel.AVISO: "aviso",
    Nivel.SOSPECHOSO: "sospechoso",
    Nivel.CRITICO: "critico",
}

# Umbrales de puntuacion -> nivel. Se evaluan de mayor a menor.
UMBRALES = [
    (70, Nivel.CRITICO),
    (40, Nivel.SOSPECHOSO),
    (20, Nivel.AVISO),
    (1, Nivel.INFO),
]


def nivel_de(puntos: int) -> Nivel:
    for minimo, nivel in UMBRALES:
        if puntos >= minimo:
            return nivel
    return Nivel.LIMPIO


@dataclass
class Senal:
    """Una observacion concreta sobre un artefacto, con su peso.

    `categoria` decide si la firma digital puede silenciarla:

    - "contexto": donde vive, como arranca, que ordena ejecutar. Vale igual
      este firmado o no. Un binario firmado que persiste desde %TEMP% sigue
      mereciendo una mirada.
    - "contenido": que hay dentro del PE (imports, entropia, secciones). Estas
      heuristicas describen capacidades, no intenciones: Chrome, explorer.exe
      y cualquier antivirus inyectan codigo y enganchan el teclado de forma
      perfectamente legitima. Sin la atenuacion por firma, el informe se llena
      de falsos positivos y deja de ser util.
    """

    codigo: str
    titulo: str
    detalle: str
    puntos: int
    categoria: str = "contexto"
    attack: str | None = None  # técnica MITRE ATT&CK cuando la señal la identifica (ej. "T1218.010")


@dataclass
class Artefacto:
    """Algo que se ejecuta (o puede ejecutarse) en esta maquina."""

    origen: str  # "Registro Run (HKCU)", "Tarea programada", "Proceso vivo"...
    nombre: str
    comando: str
    ruta: str | None = None  # ejecutable resuelto en disco
    detalle: dict = field(default_factory=dict)

    # Rellenado por los analizadores
    existe: bool = False
    tamano: int | None = None
    sha256: str | None = None
    firma: dict | None = None
    pe: dict | None = None
    yara: list = field(default_factory=list)

    # Veredicto
    senales: list = field(default_factory=list)
    attack: list = field(default_factory=list)  # técnicas MITRE ATT&CK: [{id, nombre, url, motivo}]
    puntos: int = 0
    nivel: Nivel = Nivel.LIMPIO

    @property
    def clave(self) -> str:
        return f"{self.origen}|{self.nombre}|{self.comando}".lower()

    def a_dict(self) -> dict:
        d = asdict(self)
        d["nivel"] = ETIQUETA[self.nivel]
        return d


@dataclass
class Informe:
    maquina: str
    usuario: str
    fecha: str
    admin: bool
    duracion: float = 0.0
    artefactos: list = field(default_factory=list)
    avisos: list = field(default_factory=list)  # errores de recoleccion

    def resumen(self) -> dict:
        cuenta = {e: 0 for e in ETIQUETA.values()}
        for a in self.artefactos:
            cuenta[ETIQUETA[a.nivel]] += 1
        return cuenta

    def a_dict(self) -> dict:
        return {
            "maquina": self.maquina,
            "usuario": self.usuario,
            "fecha": self.fecha,
            "admin": self.admin,
            "duracion": round(self.duracion, 2),
            "resumen": self.resumen(),
            "avisos": self.avisos,
            "artefactos": [a.a_dict() for a in self.artefactos],
        }
