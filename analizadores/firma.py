"""Verificacion de firma Authenticode en lote.

Se apoya en Get-AuthenticodeSignature, que aplica las mismas cadenas de confianza
que usa Windows al ejecutar el binario. Se consulta por lotes porque abrir un
proceso de PowerShell por fichero seria inviable.
"""

from __future__ import annotations

import os
import tempfile

from nucleo.util import ps_json

TAMANO_LOTE = 150

# Emisores que implican binario de plataforma. Se usan para SUPRIMIR ruido,
# nunca para elevar sospecha.
EDITORES_MICROSOFT = (
    "microsoft windows",
    "microsoft corporation",
    "microsoft code signing",
    "microsoft windows publisher",
    "microsoft windows hardware compatibility",
)

PS_FIRMA = r"""
$lista = Get-Content -LiteralPath $env:ATALAYA_LISTA -Encoding UTF8
$r = @()
foreach ($linea in $lista) {
  # Get-Content decora cada linea con propiedades del proveedor de ficheros;
  # sin este cast, ConvertTo-Json serializa PSPath y compania en vez de la ruta.
  $p = [string]$linea
  if (-not $p) { continue }
  try {
    $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
    $r += [pscustomobject]@{
      Ruta     = $p
      Estado   = [string]$s.Status
      Firmante = if ($s.SignerCertificate) { [string]$s.SignerCertificate.Subject } else { '' }
      Emisor   = if ($s.SignerCertificate) { [string]$s.SignerCertificate.Issuer } else { '' }
      Caduca   = if ($s.SignerCertificate) { [string]$s.SignerCertificate.NotAfter } else { '' }
    }
  } catch {
    $r += [pscustomobject]@{ Ruta = $p; Estado = 'Error'; Firmante = ''; Emisor = ''; Caduca = '' }
  }

}
$r | ConvertTo-Json -Depth 2 -Compress
"""


def verificar(rutas: list[str]) -> dict[str, dict]:
    """Devuelve {ruta_minuscula: {estado, firmante, emisor, es_microsoft, confiable}}."""
    unicas = sorted({r for r in rutas if r and os.path.isfile(r)})
    resultado: dict[str, dict] = {}

    for i in range(0, len(unicas), TAMANO_LOTE):
        lote = unicas[i:i + TAMANO_LOTE]
        fd, listado = tempfile.mkstemp(suffix=".txt", text=False)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write("\n".join(lote).encode("utf-8-sig"))
            os.environ["ATALAYA_LISTA"] = listado
            filas = ps_json(PS_FIRMA, timeout=300)
        finally:
            os.environ.pop("ATALAYA_LISTA", None)
            try:
                os.unlink(listado)
            except OSError:
                pass

        for f in filas:
            ruta = (f.get("Ruta") or "").strip()
            if not ruta:
                continue
            estado = (f.get("Estado") or "Unknown").strip()
            firmante = (f.get("Firmante") or "").strip()
            resultado[ruta.lower()] = {
                "estado": estado,
                "firmante": _nombre_comun(firmante),
                "firmante_completo": firmante,
                "emisor": _nombre_comun((f.get("Emisor") or "").strip()),
                "caduca": (f.get("Caduca") or "").strip(),
                "es_microsoft": _es_microsoft(firmante),
                "confiable": estado == "Valid",
                "rota": estado in ("HashMismatch", "NotTrusted", "NotSigned_Invalid"),
            }

    return resultado


def _es_microsoft(sujeto: str) -> bool:
    s = sujeto.lower()
    return any(e in s for e in EDITORES_MICROSOFT)


def _nombre_comun(dn: str) -> str:
    """Extrae el CN= de un Distinguished Name."""
    if not dn:
        return ""
    for parte in dn.split(","):
        parte = parte.strip()
        if parte.upper().startswith("CN="):
            return parte[3:].strip()
    return dn[:80]
