#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
escudo-informe — junta los resultados de las herramientas Escudo en un
solo informe para el dueño de la empresa.

Lee la salida JSON de ssh-sentinel, correo-escudo, cuentas-escudo y
windows-escudo, y arma:
  - un informe para el CLIENTE (nota A–F, resumen, qué atender primero, detalle), y
  - opcionalmente, una GUÍA TÉCNICA para el técnico (--tecnico), con el
    "cómo resolver" de cada hallazgo (pasos, MITRE y estándar).

No usa internet. Solo lee los archivos que le das.

Uso:
    ./escudo-informe.py salida1.json salida2.json ... -o informe.html
    ./escudo-informe.py carpeta_de_resultados/ -o informe.html --tecnico
    cat salida.json | ./escudo-informe.py -

El informe del cliente es limpio y sin tecnicismos; la guía técnica
(informe-tecnico.html) es tu documento de trabajo para resolver lo que
el informe del cliente señala.

Para generar las entradas:
    ssh-sentinel ... --format json          > ssh.json
    correo-escudo analizar ... --format json > correo.json
    cuentas-escudo ... --salida json         > cuentas.json
    windows-escudo.ps1 -Json                 > windows.json

Códigos de salida: 0 bien · 1 mejorable · 3 grave · 2 error.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

VERSION = "1.1.0"

# Escala de gravedad única (de mayor a menor) y su peso.
SEV_ORDER = {"critico": 4, "alto": 3, "medio": 2, "bajo": 1, "info": 0}
SEV_LABEL = {"critico": "CRÍTICO", "alto": "ALTO", "medio": "MEDIO",
             "bajo": "BAJO", "info": "INFO"}

# Traducción de las severidades de cada herramienta a la escala única.
SEV_MAP = {
    "critical": "critico", "high": "alto", "medium": "medio", "low": "bajo",
    "info": "info", "informational": "info",
    "critico": "critico", "alto": "alto", "medio": "medio", "bajo": "bajo",
    # correo-escudo (veredicto por correo)
    "dangerous": "alto", "suspicious": "medio", "clean": None,
}

TOOL_LABEL = {
    "ssh-sentinel": "Accesos SSH",
    "correo-escudo": "Correo (phishing)",
    "cuentas-escudo": "Cuentas (Microsoft 365 / Google)",
    "windows-escudo": "Equipos Windows",
}


class ErrorUso(Exception):
    """Error de uso → código de salida 2."""


# =============================================================================
#  Modelo
# =============================================================================
@dataclass
class Hallazgo:
    tool: str
    sev: str          # critico/alto/medio/bajo/info
    code: str
    title: str
    target: str = ""  # a qué equipo/usuario/correo se refiere
    mitre: str = ""   # técnica MITRE ATT&CK (ej. T1110)
    norma: str = ""   # estándar/cumplimiento (ej. CIS, PCI DSS)
    # Para correo: hallazgos específicos dentro del mismo correo
    # (lista de (sev, code, title)) que se detallan en la guía técnica.
    detalles: list = field(default_factory=list)


@dataclass
class Resumen:
    verdict: str
    code: int
    grade: str
    por_sev: dict = field(default_factory=dict)
    por_tool: dict = field(default_factory=dict)
    total: int = 0
    tools_vistas: list = field(default_factory=list)


def limpiar(s, maxlen: int = 300) -> str:
    """Normaliza texto que viene de los informes (entrada no confiable)."""
    if s is None:
        return ""
    if not isinstance(s, str):
        s = str(s)
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", s)
    s = s.replace("\r", " ").replace("\n", " ").strip()
    if len(s) > maxlen:
        s = s[: maxlen - 1] + "…"
    return s


def map_sev(raw: str):
    if raw is None:
        return None
    return SEV_MAP.get(str(raw).strip().lower(), None)


# =============================================================================
#  Lectura de los distintos formatos
# =============================================================================
def iter_json_docs(text: str):
    """Genera cada documento JSON de un texto: un objeto, un array, o JSON Lines."""
    text = text.lstrip("﻿").strip()
    if not text:
        return
    # ¿un solo JSON (objeto o array) válido?
    try:
        data = json.loads(text)
        if isinstance(data, list):
            yield from data
        else:
            yield data
        return
    except ValueError:
        pass
    # JSON Lines
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            yield json.loads(ln)
        except ValueError:
            continue


def hallazgos_de_doc(doc: dict):
    """Convierte un documento JSON de cualquier herramienta en hallazgos."""
    if not isinstance(doc, dict):
        return
    tool = str(doc.get("tool", "")).strip()

    # ssh-sentinel: un objeto con alerts[]
    if tool == "ssh-sentinel" and isinstance(doc.get("alerts"), list):
        host = limpiar(doc.get("host", ""), 60)
        for a in doc["alerts"]:
            if not isinstance(a, dict):
                continue
            sev = map_sev(a.get("severity"))
            if sev is None:
                continue
            tgt = limpiar(a.get("ip", ""), 60) or host
            yield Hallazgo(tool, sev, limpiar(a.get("id", ""), 40),
                           limpiar(a.get("title", ""), 300), tgt,
                           mitre=limpiar(a.get("mitre", ""), 60))
        return

    # correo-escudo: una línea por correo (type == email)
    if tool == "correo-escudo" and doc.get("type") == "email":
        sev = map_sev(doc.get("verdict_code"))
        if sev is None:
            return
        archivo = limpiar(os.path.basename(doc.get("file", "")) or "correo", 80)
        # Hallazgos específicos dentro del correo, para la guía técnica.
        detalles = []
        for f in doc.get("findings", []) or []:
            if not isinstance(f, dict):
                continue
            cod = limpiar(f.get("id") or f.get("code", ""), 40)
            if not cod:
                continue
            isev = map_sev(f.get("severity")) or sev
            detalles.append((isev, cod, limpiar(f.get("title", ""), 240)))
        yield Hallazgo(tool, sev, "CORREO-" + str(doc.get("verdict_code", "")).upper(),
                       "Correo " + limpiar(doc.get("verdict", ""), 40), archivo,
                       detalles=detalles)
        return

    # cuentas-escudo y windows-escudo: type == finding
    if doc.get("type") == "finding":
        sev = map_sev(doc.get("severity"))
        if sev is None:
            return
        titulo = limpiar(doc.get("title") or doc.get("message", ""), 300)
        tgt = limpiar(doc.get("host") or doc.get("user", ""), 80)
        yield Hallazgo(tool or "desconocido", sev,
                       limpiar(doc.get("code", ""), 40), titulo, tgt,
                       mitre=limpiar(doc.get("mitre", ""), 60),
                       norma=limpiar(doc.get("compliance", ""), 120))
        return
    # Los resúmenes (type == summary) y otros docs se ignoran.


MAX_BYTES = 50 * 1024 * 1024


def leer_texto(ruta: str) -> str:
    if ruta == "-":
        data = sys.stdin.buffer.read(MAX_BYTES + 1)
    else:
        try:
            with open(ruta, "rb") as f:
                data = f.read(MAX_BYTES + 1)
        except OSError as e:
            raise ErrorUso(f"no se pudo leer {ruta}: {e}") from e
    if len(data) > MAX_BYTES:
        raise ErrorUso(f"{ruta}: archivo demasiado grande")
    return data.decode("utf-8", errors="replace")


def juntar_archivos(entradas: list) -> list:
    out, vistos = [], set()

    def agregar(ruta):
        if ruta == "-":
            out.append("-")
            return
        try:
            clave = os.path.realpath(ruta)
        except OSError:
            clave = ruta
        if clave not in vistos:        # evita contar dos veces el mismo archivo
            vistos.add(clave)
            out.append(ruta)

    for t in entradas:
        if t == "-":
            agregar("-")
        elif os.path.isdir(t):
            for nombre in sorted(os.listdir(t)):
                q = os.path.join(t, nombre)
                if os.path.isfile(q) and nombre.lower().endswith((".json", ".jsonl")):
                    agregar(q)
        else:
            agregar(t)
    return out


def cargar(entradas: list) -> list:
    hallazgos = []
    for ruta in juntar_archivos(entradas):
        texto = leer_texto(ruta)
        for doc in iter_json_docs(texto):
            hallazgos.extend(hallazgos_de_doc(doc))
    return hallazgos


# =============================================================================
#  Resumen y nota
# =============================================================================
def resumir(hallazgos: list) -> Resumen:
    por_sev = Counter(h.sev for h in hallazgos)
    por_tool = Counter(h.tool for h in hallazgos)
    peor = max((SEV_ORDER[h.sev] for h in hallazgos), default=0)
    if peor >= 4:
        verdict, code, grade = "GRAVE", 3, "F"
    elif peor == 3:
        verdict, code, grade = "GRAVE", 3, "D"
    elif peor == 2:
        verdict, code, grade = "MEJORABLE", 1, "C"
    elif peor == 1:
        verdict, code, grade = "MEJORABLE", 1, "B"
    else:
        verdict, code, grade = "BIEN", 0, "A"
    return Resumen(verdict, code, grade,
                   dict(por_sev), dict(por_tool), len(hallazgos),
                   sorted(por_tool.keys()))


def frase_resumen(r: Resumen) -> str:
    if r.total == 0:
        return ("No se encontraron problemas en las revisiones realizadas. "
                "Esto no garantiza seguridad total: es una foto de lo revisado hoy.")
    c = r.por_sev.get("critico", 0)
    a = r.por_sev.get("alto", 0)
    if c:
        return (f"Se encontraron {c} problema(s) crítico(s) y {a} alto(s) que "
                f"conviene atender cuanto antes.")
    if a:
        return f"Se encontraron {a} problema(s) de prioridad alta que conviene atender pronto."
    if r.por_sev.get("medio", 0) or r.por_sev.get("bajo", 0):
        return "Se encontraron mejoras recomendadas, ninguna urgente."
    return "Solo hay avisos informativos; nada que corregir."


def prioridades(hallazgos: list, n: int = 5) -> list:
    """Lo más grave primero (críticos y altos), hasta n."""
    orden = sorted(hallazgos, key=lambda h: (-SEV_ORDER[h.sev], h.tool, h.code))
    return [h for h in orden if SEV_ORDER[h.sev] >= 3][:n]


# =============================================================================
#  Base de soluciones (para la guía técnica)
#  Por cada código: (qué es en una línea, [pasos para resolver]).
#  Lo que no esté por código se resuelve por familia (prefijo) o por herramienta.
# =============================================================================
REMEDIOS = {
    # ---- ssh-sentinel ----
    "SSH-COMPROMISE": ("Acceso exitoso tras muchos fallos: cuenta probablemente comprometida.",
        ["Asume que la cuenta está comprometida hasta probar lo contrario.",
         "Cambia la contraseña de esa cuenta y cierra todas sus sesiones.",
         "Revisa qué hizo esa sesión (comandos, archivos, nuevos usuarios/llaves).",
         "Bloquea la IP de origen en el firewall y pasa el SSH a solo llaves."]),
    "SSH-BRUTE": ("Fuerza bruta: una IP probó muchas contraseñas.",
        ["Bloquea la IP de origen (firewall o fail2ban).",
         "Desactiva el login por contraseña y usa solo llaves SSH.",
         "Limita el acceso SSH por IP y considera cambiar el puerto."]),
    "SSH-SPRAY": ("Password spraying: pocas claves contra muchos usuarios.",
        ["Bloquea la IP de origen.",
         "Obliga contraseñas fuertes y activa bloqueo tras varios intentos.",
         "Pasa a autenticación por llaves SSH."]),
    "SSH-PASSWORD": ("Acceso con contraseña en vez de llave (más débil).",
        ["Crea llaves SSH para esos usuarios.",
         "Desactiva PasswordAuthentication en /etc/ssh/sshd_config y reinicia ssh."]),
    # ---- cuentas-escudo (Microsoft 365 / Google) ----
    "BRUTE-SUCCESS": ("Adivinaron la contraseña por fuerza bruta y entraron.",
        ["Cambia la contraseña y cierra todas las sesiones de la cuenta.",
         "Activa/confirma el doble factor (MFA).",
         "Revisa reglas de reenvío nuevas en el buzón (señal de robo)."]),
    "SPRAY-SUCCESS": ("Entraron por password spraying.",
        ["Cambia la contraseña y cierra sesiones; activa MFA.",
         "Obliga contraseñas fuertes en toda la organización."]),
    "LEGACY-AUTH-SUCCESS": ("Entró por IMAP/POP/SMTP viejo, saltándose el MFA.",
        ["Cambia la contraseña y cierra sesiones.",
         "Bloquea la autenticación heredada (legacy auth) en Microsoft 365 / Google.",
         "Confirma que el MFA quede obligatorio para esa cuenta."]),
    "IMPOSSIBLE-TRAVEL": ("La misma cuenta desde dos países lejanos en poco tiempo.",
        ["Verifica con la persona si viajó o usó VPN.",
         "Si no, trátalo como robo: cambia clave, cierra sesiones y activa MFA."]),
    "MFA-FATIGUE": ("Bombardeo de avisos de MFA hasta que alguien aceptó uno.",
        ["Cambia la contraseña y cierra sesiones.",
         "Cambia el MFA a uno con número (number matching), no de un toque.",
         "Educa a la persona a rechazar avisos que no pidió."]),
    "ALL-FOREIGN": ("Todos los accesos vienen de fuera del país.",
        ["Confirma si es esperado (empleados remotos).",
         "Si no, revisa cada cuenta y aplica acceso condicional por país."]),
    "NEW-COUNTRY": ("Acceso desde un país nuevo para esa cuenta.",
        ["Verifica con la persona.",
         "Si no lo reconoce: cambia clave, cierra sesiones y activa MFA."]),
    "PROVIDER-FLAGGED": ("El propio proveedor (Google/Microsoft) marcó el acceso como sospechoso.",
        ["Trátalo como posible robo: cambia clave y cierra sesiones.",
         "Revisa la actividad reciente de la cuenta."]),
    # ---- windows-escudo (endurecimiento / CIS) ----
    "SMB1-ON": ("SMBv1 activo: el agujero de WannaCry.",
        ["Desactiva SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol.",
         "Reinicia y confirma que nada viejo dependía de SMBv1."]),
    "AV-DISABLED": ("Antivirus (Defender) apagado.",
        ["Enciende Microsoft Defender (o el antivirus de la empresa).",
         "Confirma que la protección en tiempo real quede activa."]),
    "AV-REALTIME-OFF": ("Protección en tiempo real del antivirus apagada.",
        ["Activa la protección en tiempo real de Defender.",
         "Revisa que no haya una política o programa que la apague."]),
    "DEF-TAMPER-OFF": ("Protección contra manipulación (Tamper Protection) apagada.",
        ["Actívala en Seguridad de Windows → Protección contra virus → Tamper Protection."]),
    "AV-UNKNOWN": ("No se pudo revisar el antivirus (sin permisos u otro AV).",
        ["Corre la herramienta como Administrador.",
         "Si usan otro antivirus, confirma a mano que esté activo y actualizado."]),
    "DISK-NOCRYPT": ("Disco sin cifrar: si roban el equipo, leen todo.",
        ["Activa BitLocker en el disco del sistema.",
         "Guarda la clave de recuperación en un lugar seguro."]),
    "RDP-NO-NLA": ("Escritorio remoto sin NLA: puerta típica del ransomware.",
        ["Activa 'Requerir NLA' en las opciones de Escritorio remoto.",
         "Limita el RDP por firewall/VPN y usa contraseñas fuertes + MFA.",
         "Si no se usa RDP, desactívalo."]),
    "RDP-ON": ("Escritorio remoto encendido.",
        ["Si no lo usan, desactívalo.",
         "Si lo usan: NLA obligatorio, acceso por VPN y MFA."]),
    "BACKUP-NONE": ("Sin respaldos: ante ransomware no hay nada que recuperar.",
        ["Configura respaldos automáticos (regla 3-2-1).",
         "Prueba restaurar un archivo para confirmar que sirven."]),
    "UAC-OFF": ("Control de cuentas (UAC) desactivado.",
        ["Actívalo en el nivel recomendado (avisar al cambiar la configuración)."]),
    "AUTOLOGON": ("Inicio de sesión automático: cualquiera que encienda el equipo entra.",
        ["Desactiva el autologon y exige contraseña al iniciar."]),
    "GUEST-ON": ("Cuenta Invitado activa.",
        ["Desactiva la cuenta Invitado."]),
    "LSA-UNPROTECTED": ("LSA sin protección (RunAsPPL): facilita robo de credenciales.",
        ["Activa RunAsPPL (LSA Protection) por registro o GPO y reinicia."]),
    "NTLM-WEAK": ("Permite NTLMv1 (autenticación vieja y débil).",
        ["Sube LmCompatibilityLevel a 5 (solo NTLMv2) por GPO."]),
    "SMB-SIGN-OFF": ("Firma SMB desactivada: permite ataques de intermediario.",
        ["Activa la firma SMB (obligatoria) por GPO."]),
    "SECUREBOOT-OFF": ("Secure Boot desactivado.",
        ["Actívalo en la UEFI/BIOS del equipo."]),
    "TPM-OFF": ("TPM no disponible/activo (base de BitLocker).",
        ["Actívalo en la UEFI/BIOS si el equipo lo tiene."]),
    "AUTORUN-ON": ("AutoRun activo: un USB puede ejecutarse solo.",
        ["Desactiva AutoRun/AutoPlay (NoDriveTypeAutoRun=255) por GPO."]),
    "PSLOG-OFF": ("Registro de PowerShell (ScriptBlock) apagado.",
        ["Actívalo por GPO para tener rastro de scripts maliciosos."]),
    "FW-OFF": ("Firewall de Windows apagado.",
        ["Enciende el firewall en los tres perfiles (dominio, privado, público)."]),
    "UPDATES-OLD": ("Faltan actualizaciones de seguridad.",
        ["Instala Windows Update y reinicia.",
         "Revisa por qué se quedó atrás (servicio detenido, red, licencia)."]),
    # ---- correo-escudo (hallazgos dentro de un .eml) ----
    "BEC-CONFIRMED": ("Fraude del jefe confirmado: piden dinero y el remitente es falso.",
        ["NO pagues ni cambies ninguna cuenta.",
         "Confirma por teléfono con un número conocido (no el del correo).",
         "Avisa a la persona suplantada y guarda el correo como evidencia."]),
    "BEC-BANKCHANGE": ("Piden pagar a una cuenta bancaria nueva (el fraude más caro).",
        ["Confirma el cambio por teléfono con un número conocido antes de pagar.",
         "Ten una política: todo cambio de cuenta se verifica por otro medio."]),
    "CRED-LINK": ("Patrón de robo de contraseñas (prisa + pide datos + enlace).",
        ["No hagas clic ni escribas tu contraseña.",
         "Entra al servicio escribiendo tú la dirección oficial, no por el enlace.",
         "Si alguien ya la puso: cambia la clave y activa MFA."]),
    "AUTH-DMARC-FAIL": ("El servidor comprobó que el remitente es falso (DMARC fail).",
        ["Trata el correo como suplantación: no respondas ni actúes.",
         "Si imita TU dominio, revisa SPF/DKIM/DMARC con correo-escudo."]),
    "AUTH-NONE": ("Sin cabeceras de autenticación: no se puede verificar el remitente.",
        ["Guarda el correo como .eml desde el buzón (con todas las cabeceras) y re-analízalo."]),
    "BRAND-SPOOF": ("Dice ser una marca/banco pero el dominio no es suyo.",
        ["No confíes en el correo; contacta a la marca por su web oficial.",
         "Reporta el dominio falso."]),
    "BRAND-LOOKALIKE": ("Dominio que imita el nombre de una marca.",
        ["Igual que BRAND-SPOOF: verifica por el canal oficial, no por el correo."]),
}

# Soluciones genéricas por familia (prefijo del código).
REMEDIOS_FAMILIA = {
    "ATT-": ("Adjunto peligroso (ejecutable, doble extensión, truco de nombre).",
        ["No abras el adjunto.",
         "Si hace falta, ábrelo en un entorno aislado (sandbox/VM).",
         "Borra el correo y avisa si llegó a varias personas."]),
    "LINK-": ("Enlace engañoso (a IP, acortado, con truco o que no coincide).",
        ["No hagas clic.",
         "Pasa el cursor para ver el destino real; entra escribiendo tú la dirección oficial."]),
    "BRAND-": ("Imita una marca o banco.",
        ["Verifica por el canal oficial, nunca por el correo."]),
    "BEC-": ("Posible fraude del jefe (pago/cambio de cuenta).",
        ["Confirma por teléfono con un número conocido antes de hacer nada con dinero."]),
    "AUTH-": ("Problema de autenticación del remitente.",
        ["Trátalo como posible suplantación y verifica por otro medio."]),
    "REPLYTO-": ("Las respuestas van a otra dirección distinta del remitente.",
        ["Desconfía; no respondas con datos ni dinero sin verificar."]),
    "FREEMAIL-": ("Se presenta como alguien de una empresa pero usa correo gratuito.",
        ["Verifica la identidad por un canal conocido."]),
    "FROM-": ("El nombre mostrado no coincide con la dirección real.",
        ["Mira siempre la dirección real, no el nombre que se muestra."]),
}

# Solución genérica por herramienta (último recurso).
REMEDIOS_TOOL = {
    "ssh-sentinel": ["Revisa el acceso en el servidor y endurece SSH (llaves, firewall)."],
    "cuentas-escudo": ["Revisa la cuenta: cambia clave, cierra sesiones y activa MFA si hay duda."],
    "windows-escudo": ["Aplica el ajuste de seguridad recomendado para ese control (ver CIS)."],
    "correo-escudo": ["No abras adjuntos ni enlaces; verifica por otro medio antes de actuar."],
}


def remedio_de(code: str, tool: str = "") -> tuple:
    """Devuelve (qué es, [pasos]) para un código, con respaldo por familia/herramienta."""
    code = (code or "").strip().upper()
    if code in REMEDIOS:
        return REMEDIOS[code]
    for pref, val in REMEDIOS_FAMILIA.items():
        if code.startswith(pref):
            return val
    pasos = REMEDIOS_TOOL.get(tool, ["Revisa el hallazgo y aplica la corrección recomendada."])
    return ("", pasos)


def items_tecnicos(hallazgos: list) -> list:
    """Expande los hallazgos a ítems concretos para la guía técnica.

    Para correo, abre cada hallazgo interno del .eml (ATT-*, BEC-*, ...).
    Para el resto, usa el hallazgo tal cual.
    Devuelve dicts con: sev, code, title, target, tool, mitre, norma.
    """
    items = []
    for h in hallazgos:
        if h.tool == "correo-escudo" and h.detalles:
            for isev, code, title in h.detalles:
                items.append({"sev": isev, "code": code, "title": title,
                              "target": h.target, "tool": h.tool,
                              "mitre": "", "norma": ""})
        else:
            items.append({"sev": h.sev, "code": h.code, "title": h.title,
                          "target": h.target, "tool": h.tool,
                          "mitre": h.mitre, "norma": h.norma})
    items.sort(key=lambda it: (-SEV_ORDER.get(it["sev"], 0), it["tool"], it["code"]))
    return items


# =============================================================================
#  Render HTML
# =============================================================================
SEV_COLOR = {"critico": "#b00020", "alto": "#d9480f", "medio": "#b08900",
             "bajo": "#2b6cb0", "info": "#555"}
GRADE_COLOR = {"A": "#2f9e44", "B": "#66a80f", "C": "#f08c00",
               "D": "#e8590c", "F": "#c92a2a"}


def _chip(sev: str) -> str:
    return (f'<span style="background:{SEV_COLOR[sev]};color:#fff;'
            f'padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600">'
            f'{SEV_LABEL[sev]}</span>')


def render_html(hallazgos: list, r: Resumen, empresa: str) -> str:
    e = html.escape
    fecha = datetime.now(timezone.utc).astimezone().strftime("%d/%m/%Y %H:%M")
    gcol = GRADE_COLOR.get(r.grade, "#555")

    partes = []
    partes.append(f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe de seguridad — {e(empresa)}</title>
<style>
 :root {{ color-scheme: light; }}
 body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         color:#1a1a1a; background:#f4f5f7; margin:0; padding:24px; line-height:1.5; }}
 .wrap {{ max-width:860px; margin:0 auto; }}
 .card {{ background:#fff; border-radius:12px; padding:24px; margin-bottom:18px;
          box-shadow:0 1px 3px rgba(0,0,0,.08); }}
 h1 {{ font-size:22px; margin:0 0 4px; }}
 h2 {{ font-size:17px; margin:0 0 12px; border-bottom:2px solid #eee; padding-bottom:6px; }}
 .sub {{ color:#666; font-size:13px; margin:0 0 16px; }}
 .grade {{ display:inline-flex; align-items:center; justify-content:center;
           width:64px; height:64px; border-radius:50%; color:#fff; font-size:34px;
           font-weight:700; background:{gcol}; }}
 .tiles {{ display:flex; gap:10px; flex-wrap:wrap; margin-top:8px; }}
 .tile {{ flex:1; min-width:90px; background:#fafafa; border:1px solid #eee;
          border-radius:8px; padding:10px; text-align:center; }}
 .tile b {{ display:block; font-size:22px; }}
 table {{ width:100%; border-collapse:collapse; font-size:14px; }}
 td,th {{ text-align:left; padding:8px 6px; border-bottom:1px solid #eee; vertical-align:top; }}
 th {{ color:#666; font-weight:600; font-size:12px; text-transform:uppercase; }}
 .muted {{ color:#777; font-size:13px; }}
 .foot {{ color:#888; font-size:12px; text-align:center; margin-top:10px; }}
 ol {{ padding-left:20px; }} ol li {{ margin-bottom:8px; }}
</style></head><body><div class="wrap">""")

    # Encabezado + nota
    partes.append(f"""<div class="card">
 <h1>Informe de seguridad</h1>
 <p class="sub">{e(empresa)} · generado el {e(fecha)}</p>
 <div style="display:flex; gap:18px; align-items:center;">
   <div class="grade">{e(r.grade)}</div>
   <div>
     <div style="font-size:19px;font-weight:700">Veredicto: {e(r.verdict)}</div>
     <div class="muted">{e(frase_resumen(r))}</div>
   </div>
 </div>
 <div class="tiles">
   <div class="tile"><b style="color:{SEV_COLOR['critico']}">{r.por_sev.get('critico',0)}</b>Críticos</div>
   <div class="tile"><b style="color:{SEV_COLOR['alto']}">{r.por_sev.get('alto',0)}</b>Altos</div>
   <div class="tile"><b style="color:{SEV_COLOR['medio']}">{r.por_sev.get('medio',0)}</b>Medios</div>
   <div class="tile"><b style="color:{SEV_COLOR['bajo']}">{r.por_sev.get('bajo',0)}</b>Bajos</div>
   <div class="tile"><b>{r.total}</b>Total</div>
 </div>
</div>""")

    # Prioridades
    top = prioridades(hallazgos)
    if top:
        filas = "".join(
            f"<li><b>{_chip(h.sev)}</b> {e(limpiar(h.title,200))}"
            + (f' <span class="muted">— {e(h.target)}</span>' if h.target else "")
            + "</li>"
            for h in top)
        partes.append(f"""<div class="card">
 <h2>Qué atender primero</h2>
 <ol>{filas}</ol>
</div>""")

    # Detalle por herramienta
    por_tool = defaultdict(list)
    for h in hallazgos:
        por_tool[h.tool].append(h)
    if por_tool:
        bloques = []
        for tool in sorted(por_tool):
            hs = sorted(por_tool[tool], key=lambda x: -SEV_ORDER[x.sev])
            filas = "".join(
                f"<tr><td>{_chip(h.sev)}</td><td><b>{e(h.code)}</b><br>"
                f"<span class='muted'>{e(limpiar(h.title,240))}</span></td>"
                f"<td class='muted'>{e(h.target)}</td></tr>"
                for h in hs)
            bloques.append(
                f"<h2>{e(TOOL_LABEL.get(tool, tool))} "
                f"<span class='muted' style='font-weight:400'>({len(hs)})</span></h2>"
                f"<table><tr><th>Nivel</th><th>Hallazgo</th><th>Dónde</th></tr>{filas}</table>")
        partes.append('<div class="card">' + "".join(bloques) + "</div>")
    else:
        partes.append('<div class="card"><h2>Detalle</h2>'
                      '<p class="muted">No hay hallazgos que mostrar.</p></div>')

    partes.append(f"""<p class="foot">
 Generado por escudo-informe v{VERSION}. Este informe resume lo detectado por
 las herramientas en la fecha indicada; no es una garantía de seguridad total.
</p></div></body></html>""")
    return "".join(partes)


def render_tecnico(hallazgos: list, r: Resumen, empresa: str) -> str:
    """Guía técnica de solución (para el técnico, no para el cliente)."""
    e = html.escape
    fecha = datetime.now(timezone.utc).astimezone().strftime("%d/%m/%Y %H:%M")
    items = items_tecnicos(hallazgos)

    partes = [f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Guía técnica de solución — {e(empresa)}</title>
<style>
 :root {{ color-scheme: light; }}
 body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
         color:#1a1a1a; background:#f4f5f7; margin:0; padding:24px; line-height:1.5; }}
 .wrap {{ max-width:900px; margin:0 auto; }}
 .card {{ background:#fff; border-radius:12px; padding:20px 24px; margin-bottom:16px;
          box-shadow:0 1px 3px rgba(0,0,0,.08); }}
 h1 {{ font-size:22px; margin:0 0 4px; }}
 h2 {{ font-size:15px; margin:18px 0 8px; color:#444;
       text-transform:uppercase; letter-spacing:.03em; }}
 .sub {{ color:#666; font-size:13px; margin:0; }}
 .item {{ border-left:4px solid #ccc; padding:10px 14px; margin:10px 0;
          background:#fafafa; border-radius:0 8px 8px 0; }}
 .item .top {{ display:flex; gap:8px; align-items:center; flex-wrap:wrap; }}
 .code {{ font-family:ui-monospace, Menlo, Consolas, monospace; font-weight:700; font-size:14px; }}
 .what {{ margin:6px 0 2px; }}
 .tags {{ color:#777; font-size:12px; margin:4px 0; display:flex;
          flex-wrap:wrap; gap:6px; }}
 .tag {{ display:inline-block; background:#eef; color:#334; border-radius:6px;
         padding:1px 7px; margin-right:8px; font-size:11px; }}
 .fix {{ margin:6px 0 0; }}
 .fix b {{ font-size:13px; color:#1a6; }}
 ol.steps {{ margin:4px 0 0; padding-left:20px; }} ol.steps li {{ margin-bottom:4px; }}
 .foot {{ color:#888; font-size:12px; text-align:center; margin-top:10px; }}
 .muted {{ color:#777; font-size:13px; }}
</style></head><body><div class="wrap">
<div class="card">
 <h1>Guía técnica de solución</h1>
 <p class="sub">{e(empresa)} · generado el {e(fecha)} · documento interno del técnico</p>
 <p class="muted">Veredicto {e(r.verdict)} (nota {e(r.grade)}) · {r.total} hallazgo(s).
 Resuelve de arriba hacia abajo: primero lo crítico.</p>
</div>"""]

    if not items:
        partes.append('<div class="card"><p class="muted">No hay hallazgos que resolver. '
                      "Buen trabajo (recuerda: es una foto de lo revisado hoy).</p></div>")
    else:
        por_sev = defaultdict(list)
        for it in items:
            por_sev[it["sev"]].append(it)
        for sev in ("critico", "alto", "medio", "bajo", "info"):
            grupo = por_sev.get(sev)
            if not grupo:
                continue
            bloques = [f'<div class="card"><h2>{SEV_LABEL[sev]} · {len(grupo)}</h2>']
            for it in grupo:
                que, pasos = remedio_de(it["code"], it["tool"])
                tags = []
                if it["target"]:
                    tags.append(f'<span class="tag">Dónde: {e(it["target"])}</span>')
                if it["mitre"]:
                    tags.append(f'<span class="tag">MITRE: {e(it["mitre"])}</span>')
                if it["norma"]:
                    tags.append(f'<span class="tag">Estándar: {e(it["norma"])}</span>')
                pasos_html = "".join(f"<li>{e(p)}</li>" for p in pasos)
                que_html = f'<div class="what muted">{e(que)}</div>' if que else ""
                titulo = e(limpiar(it["title"], 240))
                bloques.append(f"""<div class="item" style="border-left-color:{SEV_COLOR[sev]}">
 <div class="top"><span class="code">{e(it["code"]) or "—"}</span>
   <span class="muted">{e(TOOL_LABEL.get(it["tool"], it["tool"]))}</span></div>
 {f'<div class="what">{titulo}</div>' if titulo else ""}
 {que_html}
 <div class="tags">{" ".join(tags)}</div>
 <div class="fix"><b>Cómo resolver</b><ol class="steps">{pasos_html}</ol></div>
</div>""")
            bloques.append("</div>")
            partes.append("".join(bloques))

    partes.append(f"""<p class="foot">
 Generado por escudo-informe v{VERSION}. Documento de trabajo interno.
 Aplica los cambios solo en equipos propios o con autorización del cliente.
</p></div></body></html>""")
    return "".join(partes)


def render_texto(r: Resumen) -> str:
    out = [f"escudo-informe v{VERSION}",
           f"Veredicto: {r.verdict}  ·  Nota: {r.grade}",
           (f"Hallazgos: {r.total}  (críticos {r.por_sev.get('critico',0)}, "
            f"altos {r.por_sev.get('alto',0)}, medios {r.por_sev.get('medio',0)}, "
            f"bajos {r.por_sev.get('bajo',0)})"),
           frase_resumen(r)]
    return "\n".join(out)


# =============================================================================
#  Escritura segura
# =============================================================================
def escribir_seguro(ruta: str, contenido: str):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(ruta, flags, 0o600)
    except OSError as e:
        raise ErrorUso(f"no se pudo escribir en {ruta}: {e}") from e
    try:
        os.write(fd, contenido.encode("utf-8"))
    finally:
        os.close(fd)


# =============================================================================
#  Main
# =============================================================================
def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="escudo-informe",
        description="Junta la salida JSON de las herramientas Escudo en un informe.",
        epilog="Códigos de salida: 0 bien · 1 mejorable · 3 grave · 2 error.")
    p.add_argument("archivos", nargs="*", help="archivos/carpetas JSON, o - para la entrada estándar")
    p.add_argument("-o", "--salida", default="informe.html", help="archivo HTML del cliente (por defecto informe.html)")
    p.add_argument("--tecnico", nargs="?", const="__AUTO__", default=None,
                   help="también genera la guía técnica de solución (para el técnico). "
                        "Opcional: ruta del archivo; si no, se deriva de -o (…-tecnico.html).")
    p.add_argument("--empresa", default="Empresa", help="nombre que aparece en el informe")
    p.add_argument("--version", action="version", version=f"escudo-informe v{VERSION}")
    args = p.parse_args(argv)

    try:
        if not args.archivos:
            raise ErrorUso("falta al menos un archivo JSON (usa - para la entrada estándar). "
                           "Prueba con -h para la ayuda.")
        hallazgos = cargar(args.archivos)
        r = resumir(hallazgos)
        htmltxt = render_html(hallazgos, r, args.empresa)
        escribir_seguro(args.salida, htmltxt)
        print(render_texto(r))
        print(f"\nInforme HTML guardado en {args.salida}", file=sys.stderr)
        if args.tecnico is not None:
            if args.tecnico == "__AUTO__":
                base, ext = os.path.splitext(args.salida)
                ruta_tec = f"{base}-tecnico{ext or '.html'}"
            else:
                ruta_tec = args.tecnico
            escribir_seguro(ruta_tec, render_tecnico(hallazgos, r, args.empresa))
            print(f"Guía técnica guardada en {ruta_tec}", file=sys.stderr)
        return r.code
    except ErrorUso as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 2


if __name__ == "__main__":
    sys.exit(main())
