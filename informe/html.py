"""Generacion del informe HTML autocontenido (sin recursos externos)."""

from __future__ import annotations

import html
import json

from nucleo.modelos import ETIQUETA, Informe, Nivel

PLANTILLA = """<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Atalaya &mdash; informe de __MAQUINA__</title>
<style>
:root {
  --fondo: #0e1117; --panel: #161b22; --borde: #262d38; --texto: #e6edf3;
  --suave: #8b949e; --acento: #58a6ff;
  --limpio: #3fb950; --info: #8b949e; --aviso: #d29922;
  --sospechoso: #f0883e; --critico: #f85149;
}
@media (prefers-color-scheme: light) {
  :root { --fondo:#f6f8fa; --panel:#fff; --borde:#d0d7de; --texto:#1f2328; --suave:#636c76; }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--fondo); color:var(--texto);
  font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
.envoltorio { max-width:1180px; margin:0 auto; padding:28px 20px 80px; }
header h1 { margin:0 0 4px; font-size:24px; letter-spacing:-.02em; }
header h1 span { color:var(--acento); }
.meta { color:var(--suave); font-size:13px; margin-bottom:22px; }
.meta code { background:var(--panel); padding:1px 6px; border-radius:4px; border:1px solid var(--borde); }
.tarjetas { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:10px; margin-bottom:24px; }
.tarjeta { background:var(--panel); border:1px solid var(--borde); border-left-width:4px;
  border-radius:8px; padding:12px 14px; cursor:pointer; user-select:none; transition:.12s; }
.tarjeta:hover { transform:translateY(-1px); }
.tarjeta.apagada { opacity:.35; }
.tarjeta .n { font-size:26px; font-weight:650; line-height:1.1; }
.tarjeta .t { font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--suave); }
.tarjeta[data-n="critico"]{border-left-color:var(--critico)} .tarjeta[data-n="critico"] .n{color:var(--critico)}
.tarjeta[data-n="sospechoso"]{border-left-color:var(--sospechoso)} .tarjeta[data-n="sospechoso"] .n{color:var(--sospechoso)}
.tarjeta[data-n="aviso"]{border-left-color:var(--aviso)} .tarjeta[data-n="aviso"] .n{color:var(--aviso)}
.tarjeta[data-n="info"]{border-left-color:var(--info)} .tarjeta[data-n="info"] .n{color:var(--info)}
.tarjeta[data-n="limpio"]{border-left-color:var(--limpio)} .tarjeta[data-n="limpio"] .n{color:var(--limpio)}
.barra { display:flex; gap:10px; margin-bottom:14px; flex-wrap:wrap; }
input[type=search] { flex:1; min-width:220px; background:var(--panel); color:var(--texto);
  border:1px solid var(--borde); border-radius:7px; padding:9px 12px; font-size:14px; }
.aviso-caja { background:var(--panel); border:1px solid var(--borde); border-left:4px solid var(--aviso);
  border-radius:8px; padding:10px 14px; margin-bottom:18px; font-size:13px; color:var(--suave); }
.fila { background:var(--panel); border:1px solid var(--borde); border-left-width:4px;
  border-radius:8px; margin-bottom:7px; overflow:hidden; }
.fila[data-n="critico"]{border-left-color:var(--critico)}
.fila[data-n="sospechoso"]{border-left-color:var(--sospechoso)}
.fila[data-n="aviso"]{border-left-color:var(--aviso)}
.fila[data-n="info"]{border-left-color:var(--info)}
.fila[data-n="limpio"]{border-left-color:var(--limpio)}
.cabecera-fila { display:flex; align-items:center; gap:12px; padding:11px 14px; cursor:pointer; }
.cabecera-fila:hover { background:rgba(127,127,127,.06); }
.pts { font-variant-numeric:tabular-nums; font-weight:650; min-width:34px; text-align:right; }
.origen { font-size:11px; color:var(--suave); text-transform:uppercase; letter-spacing:.05em;
  min-width:150px; flex-shrink:0; }
.nombre { font-weight:600; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; flex-shrink:0; max-width:280px; }
.ruta { color:var(--suave); font-family:ui-monospace,Consolas,monospace; font-size:12px;
  overflow:hidden; text-overflow:ellipsis; white-space:nowrap; flex:1; direction:rtl; text-align:left; }
.cuerpo { display:none; padding:4px 14px 16px; border-top:1px solid var(--borde); }
.fila.abierta .cuerpo { display:block; }
.senal { padding:9px 0 9px 12px; border-left:2px solid var(--borde); margin:9px 0; }
.senal.buena { border-left-color:var(--limpio); }
.senal b { display:block; font-size:13px; }
.senal small { color:var(--suave); }
.senal .peso { float:right; font-variant-numeric:tabular-nums; color:var(--suave); font-size:12px; }
dl { display:grid; grid-template-columns:auto 1fr; gap:2px 14px; margin:12px 0 0; font-size:12.5px; }
dt { color:var(--suave); }
dd { margin:0; font-family:ui-monospace,Consolas,monospace; word-break:break-all; }
table.sec { width:100%; border-collapse:collapse; margin-top:10px; font-size:12px; }
table.sec th, table.sec td { text-align:left; padding:4px 8px; border-bottom:1px solid var(--borde); }
table.sec th { color:var(--suave); font-weight:500; }
.alta { color:var(--sospechoso); font-weight:600; }
footer { margin-top:32px; color:var(--suave); font-size:12px; text-align:center; }
.vacio { text-align:center; color:var(--suave); padding:40px; }
@media (max-width:760px){ .origen,.ruta{display:none} .nombre{max-width:none} }
</style>
</head>
<body>
<div class="envoltorio">
<header>
  <h1><span>Atalaya</span> &mdash; superficie de ejecucion</h1>
  <div class="meta">
    <code>__MAQUINA__</code> &middot; usuario <code>__USUARIO__</code> &middot; __FECHA__
    &middot; __N__ artefactos en __DUR__ s &middot; __ADMIN__
  </div>
</header>
__AVISOS__
<div class="tarjetas" id="tarjetas"></div>
<div class="barra"><input type="search" id="buscar" placeholder="Filtrar por nombre, ruta, origen o senal..."></div>
<div id="lista"></div>
<footer>Atalaya &middot; herramienta de auditoria, no sustituye a un antivirus residente</footer>
</div>
<script>
const DATOS = __DATOS__;
const ORDEN = ["critico","sospechoso","aviso","info","limpio"];
const TITULO = {critico:"Criticos",sospechoso:"Sospechosos",aviso:"Avisos",info:"Informativos",limpio:"Limpios"};
let activos = new Set(["critico","sospechoso","aviso"]);
// Un equipo limpio no debe abrir un informe vacio: si no hay nada por encima
// del umbral, mostramos tambien lo informativo para que quede el inventario.
if (!DATOS.artefactos.some(a => activos.has(a.nivel))) activos.add("info");

function esc(s){ const d=document.createElement("div"); d.textContent = s==null?"":String(s); return d.innerHTML; }

function tarjetas(){
  const c = document.getElementById("tarjetas"); c.innerHTML = "";
  ORDEN.forEach(n => {
    const total = DATOS.artefactos.filter(a => a.nivel===n).length;
    const d = document.createElement("div");
    d.className = "tarjeta" + (activos.has(n) ? "" : " apagada");
    d.dataset.n = n;
    d.innerHTML = `<div class="n">${total}</div><div class="t">${TITULO[n]}</div>`;
    d.onclick = () => { activos.has(n) ? activos.delete(n) : activos.add(n); tarjetas(); pintar(); };
    c.appendChild(d);
  });
}

function detalle(a){
  let h = "";
  a.senales.slice().sort((x,y)=>y.puntos-x.puntos).forEach(s => {
    h += `<div class="senal ${s.puntos<0?"buena":""}">
      <span class="peso">${s.puntos>0?"+":""}${s.puntos}</span>
      <b>${esc(s.titulo)}</b><small>${esc(s.detalle)}</small></div>`;
  });
  h += "<dl>";
  h += `<dt>Comando</dt><dd>${esc(a.comando)}</dd>`;
  if (a.ruta) h += `<dt>Fichero</dt><dd>${esc(a.ruta)}${a.existe?"":" (no existe)"}</dd>`;
  if (a.sha256) h += `<dt>SHA256</dt><dd>${esc(a.sha256)}</dd>`;
  if (a.tamano) h += `<dt>Tamano</dt><dd>${(a.tamano/1024).toFixed(1)} KB</dd>`;
  if (a.firma) h += `<dt>Firma</dt><dd>${esc(a.firma.estado)}${a.firma.firmante?" &mdash; "+esc(a.firma.firmante):""}</dd>`;
  if (a.pe && !a.pe.error) {
    h += `<dt>PE</dt><dd>${esc(a.pe.maquina)} &middot; ${esc(a.pe.subsistema)} &middot; ${a.pe.es_dll?"DLL":"EXE"}
          &middot; compilado ${esc(a.pe.compilado||"?")} &middot; ${a.pe.total_funciones} imports</dd>`;
  }
  Object.entries(a.detalle||{}).forEach(([k,v]) => {
    if (v!==null && v!=="" ) h += `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`;
  });
  h += "</dl>";
  if (a.pe && a.pe.secciones && a.pe.secciones.length) {
    h += `<table class="sec"><tr><th>Seccion</th><th>Entropia</th><th>Virtual</th><th>Disco</th><th>Flags</th></tr>`;
    a.pe.secciones.forEach(s => {
      h += `<tr><td>${esc(s.nombre)}</td>
        <td class="${s.entropia>=7.2?"alta":""}">${s.entropia}</td>
        <td>${s.tam_virtual}</td><td>${s.tam_raw}</td>
        <td>${s.ejecutable?"X":""}${s.escribible?"W":""}</td></tr>`;
    });
    h += "</table>";
  }
  return h;
}

function pintar(){
  const q = document.getElementById("buscar").value.toLowerCase().trim();
  const lista = document.getElementById("lista");
  // Al buscar se ignora el filtro de nivel: quien escribe "svchost" quiere
  // encontrarlo este donde este, no solo entre los avisos.
  const vis = DATOS.artefactos.filter(a => {
    if (!q) return activos.has(a.nivel);
    return (a.nombre+" "+a.comando+" "+(a.ruta||"")+" "+a.origen+" "+
            a.senales.map(s=>s.titulo).join(" ")).toLowerCase().includes(q);
  });
  if (!vis.length) {
    lista.innerHTML = '<div class="vacio">' +
      (q ? 'Ningun artefacto coincide con «' + esc(q) + '».'
         : 'Nada que mostrar con los filtros actuales.') + '</div>';
    return;
  }
  if (q) {
    const nota = document.createElement("div");
    nota.className = "vacio"; nota.style.padding = "0 0 10px";
    nota.textContent = vis.length + " coincidencias en todos los niveles";
    lista.innerHTML = ""; lista.appendChild(nota);
  } else { lista.innerHTML = ""; }
  vis.forEach(a => {
    const d = document.createElement("div");
    d.className = "fila"; d.dataset.n = a.nivel;
    d.innerHTML = `<div class="cabecera-fila">
        <span class="pts">${a.puntos}</span>
        <span class="origen">${esc(a.origen)}</span>
        <span class="nombre">${esc(a.nombre)}</span>
        <span class="ruta">${esc(a.ruta||a.comando)}</span>
      </div><div class="cuerpo">${detalle(a)}</div>`;
    d.querySelector(".cabecera-fila").onclick = () => d.classList.toggle("abierta");
    lista.appendChild(d);
  });
}

document.getElementById("buscar").addEventListener("input", pintar);
tarjetas(); pintar();
</script>
</body>
</html>
"""


def generar(informe: Informe, destino: str) -> str:
    datos = informe.a_dict()
    datos["artefactos"].sort(key=lambda a: (-a["puntos"], a["origen"], a["nombre"]))

    avisos = ""
    if informe.avisos:
        items = "".join(f"<div>&bull; {html.escape(a)}</div>" for a in informe.avisos)
        avisos = f'<div class="aviso-caja"><b>Limitaciones de esta recogida</b>{items}</div>'

    salida = (PLANTILLA
              .replace("__MAQUINA__", html.escape(informe.maquina))
              .replace("__USUARIO__", html.escape(informe.usuario))
              .replace("__FECHA__", html.escape(informe.fecha))
              .replace("__N__", str(len(informe.artefactos)))
              .replace("__DUR__", f"{informe.duracion:.1f}")
              .replace("__ADMIN__", "ejecutado como administrador" if informe.admin
                       else "<b>sin privilegios de administrador</b> (vision parcial)")
              .replace("__AVISOS__", avisos)
              .replace("__DATOS__", json.dumps(datos, ensure_ascii=False)))

    with open(destino, "w", encoding="utf-8") as f:
        f.write(salida)
    return destino
