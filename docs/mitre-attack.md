# Mapeo a MITRE ATT&CK

Cada hallazgo de Atalaya cita su técnica de [MITRE ATT&CK](https://attack.mitre.org/)
con un ID concreto (`Txxxx[.xxx]`) y su motivo. El mapeo vive en código
([`reglas/attack.py`](../reglas/attack.py)) y viaja en el export JSON de cada
artefacto, así que es consumible por un SIEM, no solo legible por una persona.

<sub>🇬🇧 **Every Atalaya finding is tagged with its MITRE ATT&CK technique**, split into
the persistence *mechanism* (how it gains execution) and the *behavioral signals*
detected. The mapping lives in `reglas/attack.py` and ships in each artifact's JSON
export.</sub>

## Dos fuentes de técnica

La técnica de un artefacto sale de dos sitios distintos, y no es lo mismo:

- **El mecanismo de arranque** (el `origen` del artefacto). Que algo persista desde
  una clave `Run` es `T1547.001` *aunque el binario sea legítimo*: la técnica
  describe **cómo** consigue ejecutarse, no si es malicioso.
- **Cada señal de comportamiento** que se dispara. Un `regsvr32` cargando un
  scriptlet remoto es `T1218.010` por lo que **hace**, no por dónde vive.

Un mismo artefacto suele acumular varias: la tarea programada del caso *Squiblydoo*
es a la vez `T1053.005` (el mecanismo) y `T1218.010` (la conducta).

## Mecanismo de persistencia → técnica

| Origen del artefacto | Técnica | Nombre |
|---|---|---|
| Registro Run / RunOnce / Política Run | `T1547.001` | Registry Run Keys / Startup Folder |
| Carpeta de inicio (usuario / todos) | `T1547.001` | Registry Run Keys / Startup Folder |
| Winlogon (Shell, Userinit, Taskman, AppSetup) | `T1547.004` | Winlogon Helper DLL |
| AppInit_DLLs / LoadAppInit_DLLs | `T1546.010` | AppInit DLLs |
| Session Manager (AppCertDlls) | `T1546.009` | AppCert DLLs |
| IFEO (Debugger, VerifierDlls) | `T1546.012` | Image File Execution Options Injection |
| Script de logon (UserInitMprLogonScript) | `T1037.001` | Logon Script (Windows) |
| Servicio | `T1543.003` | Create or Modify System Process: Windows Service |
| Driver (kernel) | `T1547.006` | Kernel Modules and Extensions |
| Tarea programada | `T1053.005` | Scheduled Task |
| Suscripción WMI (`__EventFilter`, `*EventConsumer`) | `T1546.003` | WMI Event Subscription |
| Browser Helper Object | `T1176` | Browser Extensions *(legado de Internet Explorer)* |

## Señal de comportamiento → técnica

| Código de señal | Técnica | Nombre |
|---|---|---|
| `SUPLANTA_SISTEMA` | `T1036.005` | Masquerading: Match Legitimate Name or Location |
| `DOBLE_EXTENSION` | `T1036.007` | Masquerading: Double File Extension |
| `CARACTER_INVISIBLE` | `T1036.002` | Masquerading: Right-to-Left Override |
| `FIRMA_ALTERADA` | `T1036` | Masquerading *(binario firmado y modificado)* |
| `RUTA_SIN_COMILLAS` | `T1574.009` | Path Interception by Unquoted Path |
| `VALOR_CRITICO_MODIFICADO` | `T1547.004` | Winlogon Helper DLL |
| `IFEO_DEBUGGER` | `T1546.012` | IFEO Injection |
| `WMI_SUSCRIPCION` | `T1546.003` | WMI Event Subscription |
| `EMPAQUETADOR`, `ENTROPIA_ALTA`, `IMPORTS_ANEMICOS` | `T1027.002` | Software Packing |
| `SECCION_RWX`, `API_INYECCION`, `API_INYECCION_PARCIAL` | `T1055` | Process Injection |
| `API_VIGILANCIA` | `T1056.001` | Input Capture: Keylogging |
| `API_ANTIDEPURACION` | `T1622` | Debugger Evasion |
| LOLBin · PowerShell (`-enc`, oculto, bypass) | `T1059.001` | PowerShell |
| LOLBin · mshta | `T1218.005` | Mshta |
| LOLBin · rundll32 | `T1218.011` | Rundll32 |
| LOLBin · regsvr32 (Squiblydoo) | `T1218.010` | Regsvr32 |
| LOLBin · certutil / descarga | `T1105` | Ingress Tool Transfer |
| LOLBin · bitsadmin | `T1197` | BITS Jobs |
| LOLBin · wmic process call create | `T1047` | Windows Management Instrumentation |
| LOLBin · msbuild / installutil / regasm… | `T1127` | Trusted Developer Utilities Proxy Execution |
| LOLBin · base64 embebido | `T1027` | Obfuscated Files or Information |

## Dónde NO se fuerza una técnica

Ser honesto con el mapeo importa tanto como ser exhaustivo. Estos casos **no** llevan
técnica de persistencia, y es correcto:

- **`Proceso vivo`** — un proceso en ejecución es superficie de análisis, no un
  mecanismo de arranque. Si además dispara señales de comportamiento (inyección,
  etc.), esas sí aportan su técnica.
- **`Session Manager (BootExecute)`** — no tiene una sub-técnica ATT&CK limpia y
  dedicada, así que no se le asigna una forzada.

Algunas señales de calidad de compilación (`SIN_MITIGACIONES`, `FECHA_FUTURA`) tampoco
mapean a ATT&CK: son indicadores de contexto, no técnicas del adversario.

## Ejemplo: qué sale en el JSON

Para el caso *Squiblydoo* (`regsvr32 /i:http … scrobj.dll` en una tarea programada),
el export incluye:

```json
"attack": [
  {
    "id": "T1053.005",
    "nombre": "Scheduled Task/Job: Scheduled Task",
    "url": "https://attack.mitre.org/techniques/T1053/005/",
    "motivo": "Mecanismo de arranque: Tarea programada"
  },
  {
    "id": "T1218.010",
    "nombre": "System Binary Proxy Execution: Regsvr32",
    "url": "https://attack.mitre.org/techniques/T1218/010/",
    "motivo": "regsvr32 cargando scriptlet remoto (Squiblydoo)"
  }
]
```

El `motivo` distingue las dos fuentes: la técnica del mecanismo cita el `origen`; la
de la conducta cita la señal que la levantó. Ese detalle es lo que hace el mapeo
auditable en vez de decorativo.

---

El siguiente paso de la Fase 2 es emitir estos hallazgos como **reglas Sigma**, para
que se ingieran directamente en un SIEM (Wazuh, Elastic) sin trabajo manual.
