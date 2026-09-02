# Diseño de la detección: de 48 falsos positivos a cero

> Cómo Atalaya puntúa la superficie de ejecución de Windows sin ahogar el informe
> en ruido. Es la decisión de diseño central del proyecto, y la que separa una
> herramienta útil de un generador de alarmas.
>
> <sub>🇬🇧 **How Atalaya scores the Windows execution surface without drowning the
> report in noise.** The core design decision of the project: separating *capability*
> signals (what a binary can do) from *context* signals (where it runs and how it
> starts), and letting a valid signature cancel the former but never the latter.</sub>

---

## El problema: los falsos positivos matan estas herramientas

Un auditor de persistencia recolecta cientos de artefactos. En este equipo, 823.
Si marca en rojo cosas que no lo son, deja de servir: nadie revisa un informe con
cincuenta alarmas cuando sabe que cuarenta y ocho son mentira. **Un informe donde
`explorer.exe` sale en crítico no es un informe: es ruido con formato.**

Y `explorer.exe` es exactamente donde tropezó la primera versión de Atalaya.

---

## Acto 1: por qué `explorer.exe` salía en crítico

El primer motor puntuaba lo que veía dentro del binario. Y dentro de `explorer.exe`
hay motivos de sobra para asustarse:

- Importa `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread`: el juego
  completo para escribir y ejecutar código dentro de otro proceso.
- Engancha el teclado (`SetWindowsHookEx`, `GetAsyncKeyState`).
- Detecta depuradores (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`).

Sumando esas señales, `explorer.exe` alcanzaba nivel crítico. Y con él, Chrome,
Steam, Spotify y **todos los antivirus del mercado**, porque todos inyectan código
y vigilan el teclado de forma perfectamente legítima. Resultado sobre este equipo:
**2 críticos y 48 avisos, todos falsos.**

### El arreglo que no funcionó

La reacción obvia es restar puntos cuando el binario está firmado. No basta.
`explorer.exe` acumulaba tanto por contenido que, aun restando una bonificación
por firma, seguía saliendo crítico. Restar es pelear contra la suma en su propio
terreno. El problema no era el peso; era **qué se estaba midiendo**.

---

## Acto 2: capacidades no son intenciones

La idea que reordena todo: las APIs que importa un binario describen lo que **puede
hacer**, no lo que **quiere hacer**. `CreateRemoteThread` es una capacidad. Un
navegador la usa para su sandbox; un implante, para inyectarse en `lsass`. El código
es idéntico. Lo que los distingue no está dentro del PE.

Lo que sí distingue es el **contexto**: dónde vive el binario, cómo arranca, qué
ordena ejecutar. Un ejecutable que persiste desde `AppData\Local\Temp` y secuestra
`Winlogon\Shell` es sospechoso *aunque no hayamos mirado un solo byte de su código*.

Atalaya etiqueta cada señal con una de dos categorías
([`nucleo/modelos.py`](../nucleo/modelos.py), campo `categoria` de `Senal`):

| Categoría | Qué mide | Ejemplos | ¿La firma la silencia? |
|---|---|---|---|
| **contexto** | dónde vive, cómo arranca, qué ordena | ruta volátil, secuestro de Winlogon, LOLBin en la línea de comandos, suplantación de nombre, firma alterada | **No, nunca** |
| **contenido** | qué hay dentro del PE | APIs de inyección, empaquetado, entropía, sección RWX, imports anémicos | **Sí** |

---

## Acto 3: la firma anula el contenido, no el contexto

Un binario firmado y validado por Windows tiene un responsable con nombre y
apellidos. Que importe `CreateRemoteThread` deja de decir nada. Que **arranque desde
la papelera de reciclaje**, sí sigue diciéndolo.

La atenuación vive en `factor_contenido()`
([`reglas/heuristicas.py`](../reglas/heuristicas.py)):

```python
def factor_contenido(a: Artefacto) -> float:
    f = a.firma or {}
    if not f.get("confiable"):
        return 0.2 if firma_de_paquete(a) else 1.0   # sin firma: cuenta entero
    if f.get("es_microsoft"):
        return 0.0                                    # Microsoft: contenido anulado
    return 0.2                                         # tercero firmado: al 20 %
```

El factor multiplica **solo** las señales de contenido. Las de contexto se suman
enteras pase lo que pase con la firma. Esa asimetría es la clave: un binario firmado
por Microsoft que corre desde `%TEMP%` sigue puntuando su ubicación.

### La segunda pieza: correlación, no acumulación

Con editor identificado hay un matiz más. Quien inyecta código suele además detectar
depuradores y traer secciones empaquetadas: es **un perfil de capacidades, no tres
pruebas independientes**. Sumarlas volvía a inflar a Chrome y Steam hasta nivel
aviso. Así que cuando hay firma, el contenido se agrega por el **máximo**, no por la
suma ([`evaluar()`](../reglas/heuristicas.py)):

```python
if factor == 1.0:
    suma_contenido = sum(s.puntos for s in contenido)   # sin firma: cada señal aporta
else:
    suma_contenido = max((s.puntos for s in contenido), default=0)  # firmado: un perfil

total = sum(s.puntos for s in contexto) + suma_contenido
```

Sin firma válida se acumula, porque ahí cada señal sí es evidencia nueva.

---

## El resultado, en tres artefactos con el mismo binario

Los tres tienen **exactamente el mismo PE**: importan el juego completo de inyección
y detección de depurador. Lo único que cambia es el contexto y la firma. Son casos
del banco de pruebas ([`pruebas/banco.py`](../pruebas/banco.py)):

| Artefacto | Ubicación | Firma | Contexto | Contenido | Total | Nivel |
|---|---|---|---|---|---|---|
| `explorer.exe` (proceso vivo) | `C:\Windows` | Microsoft | 0 | 55 ×0 = 0 | **0** | limpio |
| Servicio de tercero firmado | `Program Files` | Acme SL | 0 | máx(40,15) ×0,2 = 8 | **8** | info |
| Secuestro de `Winlogon\Shell` | `C:\ProgramData\wsc.exe` | sin firma | 92 | 40+15 = 55 | **147** | crítico |

Mismo código, tres veredictos, y ninguno equivocado. El malware no puede comprar su
salida con una firma robada: aunque la firma fuese válida, el contexto (secuestrar
Winlogon, vivir en ProgramData sin firma) sigue contando. Y un binario legítimo
troyanizado no cuela, porque romper la firma dispara `FIRMA_ALTERADA` (+65 de
contexto por *HashMismatch*).

**De 2 críticos y 48 avisos falsos a 0 hallazgos, sin perder una sola detección del
banco.**

---

## Los controles negativos son parte del motor

Un motor probado solo contra malware siempre parece funcionar. Por eso el banco
incluye tres casos que **no deben alarmar**, tan importantes como las detecciones:

- **`explorer.exe` de Microsoft** — el caso que originó todo el rediseño.
- **Servicio de tercero firmado en Program Files** — la firma válida debe atenuar,
  no anular del todo.
- **Windows Defender en una subcarpeta de `ProgramData`** — este obligó a un detalle
  fino: la regla de ubicación solo marca la **raíz** de ProgramData
  (`padre == PROGRAMDATA` en [`_clasificar_ubicacion`](../reglas/heuristicas.py)),
  porque Defender y medio Windows viven en subcarpetas legítimas de ahí. Marcar
  ProgramData entero habría reintroducido decenas de falsos positivos.

Cada regla nueva se valida contra los tres. Si un control negativo se enciende, la
regla está mal, por muy buena que parezca la detección que la motivó.

---

## Límites honestos

El modelo es deliberado, y por tanto tiene fronteras claras:

- **Capacidades, no intenciones.** Un aviso significa «esto merece una mirada», nunca
  «esto es malware». Atalaya prioriza revisión humana; no dicta veredictos.
- **La firma hace todo el trabajo de supresión.** No hay lista blanca por hash ni
  feed de reputación, así que un binario desconocido y correctamente firmado pasa
  como limpio. Es una decisión consciente: el corpus de listas blancas es
  inabordable para un proyecto individual.
- **Nada sin fichero en memoria.** Un implante que vive dentro de un proceso legítimo
  no deja rastro en disco ni en la persistencia. Eso exige telemetría en tiempo real
  (ETW), que es la Fase 2 del proyecto.

---

## Qué demuestra este diseño

La lección que costó el rediseño no es sobre Windows: es sobre **ingeniería de
detección**. Separar señal correlacionada de señal independiente, tratar la
supresión como un problema de modelado y no de umbrales, y validar contra controles
negativos con el mismo rigor que contra las detecciones. Ese es el trabajo real de
quien escribe detecciones para un SOC, y es lo que Atalaya practica en pequeño.

El siguiente paso natural es hablar el idioma del *blue team*: mapear cada tipo de
artefacto a su técnica de [MITRE ATT&CK](https://attack.mitre.org/) y exportar los
hallazgos como reglas Sigma. Esa es la Fase 2.
