#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Monitor SNMP de impresoras HP usando SnmpWalk.exe
- 1 solo walk completo por IP (evita el bug de -os: excluyente)
- Fase 1: detección
- Fase 2: reutiliza los datos del walk para extraer todo
"""

import html
import csv
import datetime
import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================
# CONFIGURACIÓN
# ============================================================

SNMPWALK_EXE = r"C:\Users\goviedo\Downloads\app\SNMP\SnmpWalk.exe"
SNMP_COMMUNITY = "public"

MAX_HILOS_DETECCION = 40     # más hilos porque cada proceso es rápido
MAX_HILOS_DETALLE   = 40     # ya no hay Fase 2 real (solo formateo)

ARCHIVO_HTML = "impresoras.html"
ARCHIVO_CSV  = "impresoras_export.csv"
ARCHIVO_XLS  = "impresoras_export.xls"

USAR_PING    = True
PING_TIMEOUT = 0.5
PING_MAX_HILOS = 100

SUBREDES = [
    "10.1.1", "10.1.2", "10.1.3", "10.1.5",
    "10.1.6", "10.1.7", "10.1.8", "10.1.9",
    "10.1.10", "10.1.11", "10.1.12",
]

UMBRAL_BAJO    = 20
UMBRAL_CRITICO = 5

# ============================================================
# OIDs
# ============================================================

OID_SYSOBJECTID = "1.3.6.1.2.1.1.2.0"
OID_SYSNAME     = "1.3.6.1.2.1.1.5.0"
OID_SYSDESCR    = "1.3.6.1.2.1.1.1.0"
OID_UBICACION   = "1.3.6.1.2.1.1.6.0"
OID_SERIAL      = "1.3.6.1.2.1.43.5.1.1.17.1"
OID_MODELO      = "1.3.6.1.2.1.25.3.2.1.3.1"
OID_SUPPLY_DESC  = "1.3.6.1.2.1.43.11.1.1.6"
OID_SUPPLY_MAX   = "1.3.6.1.2.1.43.11.1.1.8"
OID_SUPPLY_LEVEL = "1.3.6.1.2.1.43.11.1.1.9"
HP_OID_PREFIX = "1.3.6.1.4.1.11"


# ============================================================
# HELPERS SNMP
# ============================================================

def _snmpwalk_completo(ip):
    """Walk completo desde 1. Devuelve stdout."""
    cmd = [SNMPWALK_EXE, f"-r:{ip}", f"-c:{SNMP_COMMUNITY}", "-os:1"]
    try:
        resultado = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="replace",
        )
        return resultado.stdout or ""
    except Exception:
        return None


def _parsear_salida(salida):
    """Convierte salida de SnmpWalk en dict {oid: valor}."""
    resultado = {}
    if not salida:
        return resultado

    for linea in salida.splitlines():
        linea = linea.strip()
        if not linea.startswith("OID="):
            continue
        try:
            partes = linea.split(",", 2)
            if len(partes) < 3:
                continue

            oid = partes[0].replace("OID=", "").lstrip(".").strip()
            tipo = partes[1].replace("Type=", "").strip()
            valor = partes[2].replace("Value=", "", 1).strip()

            if tipo == "OctetString":
                if valor and re.match(r"^\s*([0-9A-Fa-f]{2}\s+){3,}", valor + " "):
                    hex_limpio = valor.replace(" ", "")
                    if len(hex_limpio) % 2 == 0 and re.match(r"^[0-9A-Fa-f]+$", hex_limpio):
                        try:
                            valor = bytes.fromhex(hex_limpio).decode("utf-8", errors="replace")
                        except Exception:
                            pass
                valor = valor.replace("\x00", "").strip()

            if valor:
                resultado[oid] = valor
        except Exception:
            continue

    return resultado


def procesar_impresora(ip):
    """
    Un solo walk completo + parseo + extracción de todos los datos.
    Devuelve dict con datos de la impresora o None si no es HP.
    """
    salida = _snmpwalk_completo(ip)
    if not salida:
        return None

    datos = _parsear_salida(salida)
    if not datos:
        return None

    # Detección HP: sysObjectID empieza con 1.3.6.1.4.1.11
    sysobjid = datos.get(OID_SYSOBJECTID)
    if not sysobjid or not sysobjid.startswith(HP_OID_PREFIX):
        return None

    # Datos básicos (todos ya están en `datos`)
    nombre    = datos.get(OID_SYSNAME)
    sysdescr  = datos.get(OID_SYSDESCR)
    ubicacion = datos.get(OID_UBICACION)
    serial    = datos.get(OID_SERIAL)
    modelo    = datos.get(OID_MODELO)

    if (not modelo or modelo == "-") and sysdescr:
        modelo = sysdescr.split(",")[0].strip()

    # Consumibles
    descs  = {k: v for k, v in datos.items() if k.startswith(OID_SUPPLY_DESC)}
    maxs   = {k: v for k, v in datos.items() if k.startswith(OID_SUPPLY_MAX)}
    levels = {k: v for k, v in datos.items() if k.startswith(OID_SUPPLY_LEVEL)}

    consumibles = []
    for oid_desc, desc in descs.items():
        partes = oid_desc.split(".")
        hr_idx, sup_idx = partes[-2], partes[-1]
        sufijo = f"{hr_idx}.{sup_idx}"

        nivel_str = levels.get(f"{OID_SUPPLY_LEVEL}.{sufijo}")
        max_str   = maxs.get(f"{OID_SUPPLY_MAX}.{sufijo}")

        try:
            nivel = int(nivel_str) if nivel_str is not None else None
            maximo = int(max_str) if max_str is not None else None
        except ValueError:
            nivel, maximo = None, None

        if nivel is not None and nivel < 0:
            nivel = None
        if maximo is not None and maximo < 0:
            maximo = None

        porcentaje = None
        if nivel is not None and maximo and maximo > 0:
            porcentaje = round((nivel / maximo) * 100, 1)

        consumibles.append({
            "descripcion": desc,
            "nivel": nivel,
            "maximo": maximo,
            "porcentaje": porcentaje,
        })

    return {
        "ip": ip,
        "nombre": nombre or "-",
        "modelo": modelo or "-",
        "serial": serial or "-",
        "ubicacion": ubicacion or "-",
        "consumibles": consumibles,
    }


# ============================================================
# PING
# ============================================================

def host_activo(ip):
    try:
        from ping3 import ping
        return ping(ip, timeout=PING_TIMEOUT) is not None
    except ImportError:
        return True
    except Exception:
        return False


def prefiltrar_ips(ips):
    if not USAR_PING:
        return ips
    try:
        import ping3  # noqa
    except ImportError:
        print("⚠ ping3 no instalado. Se omite pre-filtrado.")
        return ips

    print(f"Pre-filtrando {len(ips)} IPs activas (ping)...")
    vivas = []
    with ThreadPoolExecutor(max_workers=PING_MAX_HILOS) as executor:
        resultados = executor.map(lambda ip: (ip, host_activo(ip)), ips)
        for ip, vivo in resultados:
            if vivo:
                vivas.append(ip)
    print(f"  {len(vivas)}/{len(ips)} hosts activos")
    return vivas


# ============================================================
# ESCANEO
# ============================================================

def escanear_ips(ips):
    t0 = datetime.datetime.now()

    print(f"\n▶ Escaneando {len(ips)} IPs (walk completo)...")
    print(f"  Concurrencia: {MAX_HILOS_DETECCION} procesos")

    encontradas = []
    with ThreadPoolExecutor(max_workers=MAX_HILOS_DETECCION) as executor:
        futuros = {executor.submit(procesar_impresora, ip): ip for ip in ips}
        for i, futuro in enumerate(as_completed(futuros), 1):
            ip = futuros[futuro]
            try:
                r = futuro.result()
                if r:
                    encontradas.append(r)
                    t = (datetime.datetime.now() - t0).total_seconds()
                    print(f"  ✓ [{len(encontradas)}] {r['ip']} — {r['modelo']} ({t:.1f}s)")
            except Exception:
                pass
            if i % 50 == 0:
                t = (datetime.datetime.now() - t0).total_seconds()
                print(f"  ... {i}/{len(ips)} procesadas · {len(encontradas)} HP · {t:.1f}s")

    t_total = (datetime.datetime.now() - t0).total_seconds()
    print(f"\n📊 Tiempo total escaneo: {t_total:.1f}s")
    return encontradas


# ============================================================
# HELPERS DE FORMATO
# ============================================================

def formatear_numero(n):
    if n is None:
        return "—"
    return f"{n:,}".replace(",", ".")


def texto_nivel(nivel, maximo):
    if nivel is None or maximo is None:
        return "—"
    return f"{formatear_numero(nivel)} / {formatear_numero(maximo)} pág."


def estado_texto(p):
    if p is None:
        return "Sin datos"
    if p <= UMBRAL_CRITICO:
        return "Crítico"
    if p <= UMBRAL_BAJO:
        return "Bajo"
    return "OK"


def color_fondo(p):
    if p is None:
        return "#f0f0f0"
    if p <= UMBRAL_CRITICO:
        return "#fdedec"
    if p <= UMBRAL_BAJO:
        return "#fef9e7"
    return "#e8f8ef"


# ============================================================
# EXPORTAR CSV
# ============================================================

def exportar_csv(impresoras):
    with open(ARCHIVO_CSV, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow([
            "IP", "Nombre", "Modelo", "Serial", "Ubicación",
            "Consumible", "Nivel", "Máximo", "Porcentaje", "Estado"
        ])
        for imp in impresoras:
            for c in imp["consumibles"]:
                writer.writerow([
                    imp["ip"], imp["nombre"], imp["modelo"], imp["serial"],
                    imp["ubicacion"], c["descripcion"],
                    formatear_numero(c["nivel"]),
                    formatear_numero(c["maximo"]),
                    f"{c['porcentaje']}%" if c["porcentaje"] is not None else "",
                    estado_texto(c["porcentaje"]),
                ])
    print(f"📄 CSV generado: {ARCHIVO_CSV}")


# ============================================================
# EXPORTAR EXCEL
# ============================================================

def exportar_excel(impresoras):
    fecha = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    filas = ""
    for imp in impresoras:
        if not imp["consumibles"]:
            filas += f"""
            <tr>
                <td>{imp['ip']}</td>
                <td>{html.escape(imp['nombre'])}</td>
                <td>{html.escape(imp['modelo'])}</td>
                <td>{html.escape(imp['serial'])}</td>
                <td>{html.escape(imp['ubicacion'])}</td>
                <td colspan="3">Sin datos</td>
                <td style="background:#f0f0f0;color:#888;text-align:center;font-weight:bold">SIN DATOS</td>
            </tr>"""
        else:
            for c in imp["consumibles"]:
                p = c["porcentaje"]
                bg = color_fondo(p)
                pct = f"{p}%" if p is not None else "—"
                nivel_txt = texto_nivel(c["nivel"], c["maximo"])

                if p is None:
                    estado_txt, estado_bg, estado_color = "SIN DATOS", "#f0f0f0", "#666"
                elif p <= UMBRAL_CRITICO:
                    estado_txt, estado_bg, estado_color = "CRÍTICO", "#c0392b", "#ffffff"
                elif p <= UMBRAL_BAJO:
                    estado_txt, estado_bg, estado_color = "BAJO", "#f39c12", "#ffffff"
                else:
                    estado_txt, estado_bg, estado_color = "OK", "#27ae60", "#ffffff"

                filas += f"""
                <tr>
                    <td>{imp['ip']}</td>
                    <td>{html.escape(imp['nombre'])}</td>
                    <td>{html.escape(imp['modelo'])}</td>
                    <td>{html.escape(imp['serial'])}</td>
                    <td>{html.escape(imp['ubicacion'])}</td>
                    <td>{html.escape(c['descripcion'])}</td>
                    <td style="background:{bg}">{nivel_txt}</td>
                    <td style="background:{bg};font-weight:bold">{pct}</td>
                    <td style="background:{estado_bg};color:{estado_color};font-weight:bold;text-align:center">{estado_txt}</td>
                </tr>"""

    html_xls = f"""<html xmlns:x="urn:schemas-microsoft-com:office:excel">
<head>
<meta charset="UTF-8">
<!--[if gte mso 9]>
<xml>
<x:ExcelWorkbook>
  <x:ExcelWorksheets>
    <x:ExcelWorksheet>
      <x:Name>Impresoras HP</x:Name>
      <x:WorksheetOptions>
        <x:DisplayGridlines/>
        <x:FreezePanes/>
        <x:FrozenNoSplit/>
        <x:SplitHorizontal>4</x:SplitHorizontal>
        <x:TopRowBottomPane>4</x:TopRowBottomPane>
        <x:ActivePane>2</x:ActivePane>
      </x:WorksheetOptions>
    </x:ExcelWorksheet>
  </x:ExcelWorksheets>
</x:ExcelWorkbook>
</xml>
<![endif]-->
<style>
  table {{ border-collapse: collapse; font-family: Calibri, Arial, sans-serif; font-size: 11pt; }}
  th {{ background: #2c3e50; color: #fff; padding: 6px 10px; border: 1px solid #ccc; font-weight: bold; text-align: left; }}
  td {{ padding: 5px 10px; border: 1px solid #ddd; }}
  .titulo {{ font-size: 14pt; font-weight: bold; }}
  .fecha {{ color: #666; font-size: 10pt; }}
</style>
</head>
<body>
  <table>
    <tr><td colspan="9" class="titulo">🖨️ Monitor de Impresoras HP</td></tr>
    <tr><td colspan="9" class="fecha">Generado: {fecha} · {len(impresoras)} impresora(s)</td></tr>
    <tr><td colspan="9"></td></tr>
    <thead>
      <tr>
        <th>IP</th><th>Nombre</th><th>Modelo</th><th>Serial</th><th>Ubicación</th>
        <th>Consumible</th><th>Nivel / Máximo</th><th>Porcentaje</th><th>Estado</th>
      </tr>
    </thead>
    <tbody>{filas}</tbody>
  </table>
</body>
</html>"""

    with open(ARCHIVO_XLS, "w", encoding="utf-8") as f:
        f.write(html_xls)
    print(f"📊 Excel generado: {ARCHIVO_XLS}")


# ============================================================
# HTML
# ============================================================

def color_porcentaje(p):
    if p is None:
        return "gris"
    if p <= UMBRAL_CRITICO:
        return "rojo"
    if p <= UMBRAL_BAJO:
        return "amarillo"
    return "verde"


def generar_html(impresoras):
    fecha = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = len(impresoras)

    filas = []
    for imp in impresoras:
        celdas_consumibles = []
        if not imp["consumibles"]:
            celdas_consumibles.append('<span class="gris">Sin datos</span>')
        else:
            for c in imp["consumibles"]:
                p = c["porcentaje"]
                clase = color_porcentaje(p)
                texto = f"{p}%" if p is not None else "—"
                desc = html.escape(c["descripcion"])
                celdas_consumibles.append(
                    f'<div class="consumible {clase}">'
                    f'<span class="nombre">{desc}</span>'
                    f'<span class="nivel">{texto}</span>'
                    f'</div>'
                )
        celda_consumibles = "".join(celdas_consumibles)

        filas.append(f"""
        <tr>
            <td><a href="http://{imp['ip']}" target="_blank">{imp['ip']}</a></td>
            <td>{html.escape(imp['nombre'])}</td>
            <td>{html.escape(imp['modelo'])}</td>
            <td class="serial">{html.escape(imp['serial'])}</td>
            <td>{html.escape(imp['ubicacion'])}</td>
            <td class="consumibles">{celda_consumibles}</td>
        </tr>""")

    html_final = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Monitor de Impresoras HP</title>
<meta http-equiv="refresh" content="300">
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
    background: #f4f6f8; margin: 0; padding: 24px; color: #222; }}
  h1 {{ margin: 0 0 4px; font-size: 22px; }}
  .meta {{ color: #666; font-size: 13px; margin-bottom: 16px; }}
  .acciones {{ margin-bottom: 16px; display: flex; gap: 10px; flex-wrap: wrap; }}
  .btn {{ display: inline-flex; align-items: center; gap: 6px;
    background: #2c3e50; color: #fff; padding: 8px 16px;
    border-radius: 5px; text-decoration: none; font-size: 13px;
    font-weight: 600; transition: background .15s; }}
  .btn:hover {{ background: #1a252f; text-decoration: none; }}
  .btn.csv {{ background: #27ae60; }}
  .btn.csv:hover {{ background: #1e8449; }}
  .btn.xls {{ background: #217346; }}
  .btn.xls:hover {{ background: #185c37; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff;
    box-shadow: 0 1px 4px rgba(0,0,0,.08); border-radius: 6px; overflow: hidden; }}
  th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #eee;
    font-size: 13px; vertical-align: top; }}
  th {{ background: #2c3e50; color: #fff; font-weight: 600; font-size: 12px;
    text-transform: uppercase; letter-spacing: .04em; }}
  tr:hover td {{ background: #f9fbfd; }}
  .serial {{ font-family: monospace; font-size: 12px; }}
  a {{ color: #2980b9; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .consumibles {{ min-width: 260px; }}
  .consumible {{ display: flex; justify-content: space-between; align-items: center;
    padding: 2px 6px; margin: 2px 0; border-radius: 3px; font-size: 12px; }}
  .consumible .nombre {{ flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .consumible .nivel {{ font-weight: 700; margin-left: 8px; }}
  .verde    {{ background: #e8f8ef; color: #1e8449; }}
  .amarillo {{ background: #fef9e7; color: #b7950b; }}
  .rojo     {{ background: #fdedec; color: #c0392b; }}
  .gris     {{ background: #f0f0f0; color: #888; }}
</style>
</head>
<body>
  <h1>🖨️ Monitor de Impresoras HP</h1>
  <div class="meta">
    {total} impresora(s) detectada(s) · Actualizado: {fecha} · Se recarga cada 5 min
  </div>
  <div class="acciones">
    <a class="btn csv" href="{ARCHIVO_CSV}" download>⬇ Descargar CSV</a>
    <a class="btn xls" href="{ARCHIVO_XLS}" download>⬇ Descargar Excel</a>
  </div>
  <table>
    <thead>
      <tr>
        <th>IP</th><th>Nombre</th><th>Modelo</th>
        <th>Serial</th><th>Ubicación</th><th>Consumibles</th>
      </tr>
    </thead>
    <tbody>
      {''.join(filas) if filas else '<tr><td colspan="6">No se detectaron impresoras.</td></tr>'}
    </tbody>
  </table>
</body>
</html>"""

    with open(ARCHIVO_HTML, "w", encoding="utf-8") as f:
        f.write(html_final)


# ============================================================
# MAIN
# ============================================================

def main():
    inicio = datetime.datetime.now()

    if not os.path.isfile(SNMPWALK_EXE):
        print(f"❌ ERROR: No se encontró SnmpWalk.exe en: {SNMPWALK_EXE}")
        return

    ips = []
    for subred in SUBREDES:
        for host in range(1, 100):
            ips.append(f"{subred}.{host}")

    print(f"Total de IPs a escanear: {len(ips)}")

    t_ping_ini = datetime.datetime.now()
    ips = prefiltrar_ips(ips)
    t_ping = (datetime.datetime.now() - t_ping_ini).total_seconds()
    print(f"  ⏱ Pre-filtro: {t_ping:.1f}s")

    encontradas = escanear_ips(ips)
    encontradas.sort(key=lambda x: tuple(int(p) for p in x["ip"].split(".")))

    generar_html(encontradas)
    exportar_csv(encontradas)
    exportar_excel(encontradas)

    fin = datetime.datetime.now()
    duracion = (fin - inicio).total_seconds()

    print(f"\n✅ {len(encontradas)} impresora(s) HP encontrada(s).")
    print(f"⏱  Tiempo total: {duracion:.1f} segundos ({duracion/60:.1f} minutos)")
    print(f"📄 HTML:  {os.path.abspath(ARCHIVO_HTML)}")
    print(f"📄 CSV:   {os.path.abspath(ARCHIVO_CSV)}")
    print(f"📊 Excel: {os.path.abspath(ARCHIVO_XLS)}")


if __name__ == "__main__":
    main()