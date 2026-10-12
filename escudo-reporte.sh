#!/usr/bin/env bash
# =============================================================================
# escudo-reporte.sh  —  corre las herramientas Escudo y arma el informe solo.
#
# En vez de correr cada herramienta a mano y juntar los JSON, este comando lo
# hace todo: ejecuta lo que tengas instalado, guarda los resultados con fecha
# y genera DOS documentos con escudo-informe:
#   - informe.html          (para el cliente)
#   - informe-tecnico.html   (tu guía de solución)
#
# Uso:
#   ./escudo-reporte.sh --empresa "Ferretería El Clavo" --dominio elclavo.com
#   ./escudo-reporte.sh --empresa "Cliente" --cuentas logins.csv --pais PA --abrir
#   ./escudo-reporte.sh --empresa "Cliente" --windows windows.json --no-ssh
#
# Opciones:
#   --empresa "Nombre"   Nombre del cliente en el informe.
#   --dominio DOMINIO    Revisa SPF/DKIM/DMARC del dominio (info PÚBLICA).
#   --correo RUTA        Analiza un .eml o una carpeta de .eml.
#   --cuentas ARCHIVO    Analiza un CSV/JSON de inicios de sesión (M365/Google).
#   --windows ARCHIVO    Incluye un windows.json ya generado en Windows.
#   --pais XX            País para "viaje imposible" (ej. PA). Default PA.
#   --no-ssh             No correr ssh-sentinel.
#   --salida CARPETA     Dónde guardar (default ~/escudo-reportes/FECHA).
#   --abrir              Abrir los dos informes al terminar.
#   -h, --help           Esta ayuda.
#
# REGLA: usa esto solo en equipos propios o con autorización escrita del cliente.
# (El modo --dominio es la excepción: usa información pública.)
#
# Puedes fijar la ruta de una herramienta si no está en el PATH, p. ej.:
#   SSH_SENTINEL=/opt/ssh-sentinel  CORREO_ESCUDO=~/correo-escudo/correo-escudo.sh ./escudo-reporte.sh ...
# =============================================================================
set -u

# --- localizar escudo-informe.py (está junto a este script) ------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFORME="${ESCUDO_INFORME:-$SCRIPT_DIR/escudo-informe.py}"

# --- herramientas: usa la variable de entorno si existe, si no busca en PATH --
SSH_SENTINEL="${SSH_SENTINEL:-ssh-sentinel}"
CORREO_ESCUDO="${CORREO_ESCUDO:-correo-escudo}"
CUENTAS_ESCUDO="${CUENTAS_ESCUDO:-cuentas-escudo}"

# --- valores por defecto -----------------------------------------------------
EMPRESA="Empresa"
DOMINIO=""
CORREO_RUTA=""
CUENTAS_ARCH=""
WINDOWS_ARCH=""
PAIS="PA"
USAR_SSH=1
ABRIR=0
SALIDA=""

msg()  { printf '%s\n' "$*" >&2; }
die()  { printf 'Error: %s\n' "$*" >&2; exit 2; }
existe() { command -v "$1" >/dev/null 2>&1; }

# --- leer argumentos ---------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --empresa)  EMPRESA="${2:-}"; shift 2 ;;
    --dominio)  DOMINIO="${2:-}"; shift 2 ;;
    --correo)   CORREO_RUTA="${2:-}"; shift 2 ;;
    --cuentas)  CUENTAS_ARCH="${2:-}"; shift 2 ;;
    --windows)  WINDOWS_ARCH="${2:-}"; shift 2 ;;
    --pais)     PAIS="${2:-}"; shift 2 ;;
    --salida)   SALIDA="${2:-}"; shift 2 ;;
    --no-ssh)   USAR_SSH=0; shift ;;
    --abrir)    ABRIR=1; shift ;;
    -h|--help)  sed -n '2,38p' "$0"; exit 0 ;;
    *) die "opción desconocida: $1 (usa -h para la ayuda)" ;;
  esac
done

[ -f "$INFORME" ] || die "no encuentro escudo-informe.py (busqué en $INFORME)"

# --- carpeta de trabajo con fecha --------------------------------------------
FECHA="$(date +%Y-%m-%d_%H%M)"
if [ -z "$SALIDA" ]; then
  SALIDA="$HOME/escudo-reportes/$FECHA"
fi
mkdir -p "$SALIDA" || die "no pude crear la carpeta $SALIDA"
JSON_DIR="$SALIDA/datos"
mkdir -p "$JSON_DIR"

COLECTADOS=0   # cuántos JSON logramos juntar

# guarda_json ARCHIVO_DESTINO  — guarda stdin si trae contenido; reporta.
guarda_json() {
  local destino="$1" etiqueta="$2"
  if [ -s "$destino" ]; then
    msg "  [ok] $etiqueta -> $(basename "$destino")"
    COLECTADOS=$((COLECTADOS + 1))
  else
    rm -f "$destino"
    msg "  [sin datos] $etiqueta (no generó salida)"
  fi
}

msg "== escudo-reporte :: $EMPRESA :: $FECHA =="
msg "Carpeta: $SALIDA"
msg ""

# --- 1) ssh-sentinel (no necesita entrada) -----------------------------------
if [ "$USAR_SSH" -eq 1 ]; then
  if existe "$SSH_SENTINEL" || [ -x "$SSH_SENTINEL" ]; then
    msg "-> ssh-sentinel (accesos SSH del sistema)"
    # ssh-sentinel suele necesitar sudo para leer el journal.
    # SC2024: a propósito; el archivo lo escribe el usuario (no root), que es lo que queremos.
    # shellcheck disable=SC2024
    sudo "$SSH_SENTINEL" --format json >"$JSON_DIR/ssh.json" 2>/dev/null
    guarda_json "$JSON_DIR/ssh.json" "ssh-sentinel"
  else
    msg "  [saltado] ssh-sentinel no encontrado"
  fi
else
  msg "  [omitido] ssh-sentinel (--no-ssh)"
fi

# --- 2) correo-escudo: dominio (público) -------------------------------------
if [ -n "$DOMINIO" ]; then
  if existe "$CORREO_ESCUDO" || [ -x "$CORREO_ESCUDO" ]; then
    msg "-> correo-escudo dominio $DOMINIO (SPF/DKIM/DMARC públicos)"
    "$CORREO_ESCUDO" dominio "$DOMINIO" --format json >"$JSON_DIR/correo-dominio.json" 2>/dev/null
    guarda_json "$JSON_DIR/correo-dominio.json" "correo-escudo (dominio)"
  else
    msg "  [saltado] correo-escudo no encontrado"
  fi
fi

# --- 3) correo-escudo: analizar .eml / carpeta -------------------------------
if [ -n "$CORREO_RUTA" ]; then
  if existe "$CORREO_ESCUDO" || [ -x "$CORREO_ESCUDO" ]; then
    [ -e "$CORREO_RUTA" ] || die "no existe la ruta de correo: $CORREO_RUTA"
    msg "-> correo-escudo analizar $CORREO_RUTA"
    "$CORREO_ESCUDO" analizar "$CORREO_RUTA" --format json >"$JSON_DIR/correo-analisis.json" 2>/dev/null
    guarda_json "$JSON_DIR/correo-analisis.json" "correo-escudo (análisis)"
  else
    msg "  [saltado] correo-escudo no encontrado"
  fi
fi

# --- 4) cuentas-escudo -------------------------------------------------------
if [ -n "$CUENTAS_ARCH" ]; then
  if existe "$CUENTAS_ESCUDO" || [ -x "$CUENTAS_ESCUDO" ]; then
    [ -e "$CUENTAS_ARCH" ] || die "no existe el archivo de cuentas: $CUENTAS_ARCH"
    msg "-> cuentas-escudo $CUENTAS_ARCH (país $PAIS)"
    "$CUENTAS_ESCUDO" "$CUENTAS_ARCH" --salida json --pais "$PAIS" >"$JSON_DIR/cuentas.json" 2>/dev/null
    guarda_json "$JSON_DIR/cuentas.json" "cuentas-escudo"
  else
    msg "  [saltado] cuentas-escudo no encontrado"
  fi
fi

# --- 5) windows.json ya generado en Windows ----------------------------------
if [ -n "$WINDOWS_ARCH" ]; then
  [ -e "$WINDOWS_ARCH" ] || die "no existe el archivo de Windows: $WINDOWS_ARCH"
  cp "$WINDOWS_ARCH" "$JSON_DIR/windows.json"
  guarda_json "$JSON_DIR/windows.json" "windows-escudo (importado)"
fi

msg ""
if [ "$COLECTADOS" -eq 0 ]; then
  die "no se generó ningún dato. Dale al menos --dominio, --cuentas, --correo, --windows, o deja correr ssh-sentinel."
fi

# --- 6) armar los dos informes -----------------------------------------------
CLIENTE="$SALIDA/informe.html"
msg "-> Generando informes con escudo-informe..."
python3 "$INFORME" "$JSON_DIR"/*.json \
  -o "$CLIENTE" --tecnico "$SALIDA/informe-tecnico.html" --empresa "$EMPRESA"
RC=$?   # 0 bien · 1 mejorable · 3 grave · 2 error

msg ""
msg "Listo. Documentos en:"
msg "  Cliente:  $CLIENTE"
msg "  Técnico:  $SALIDA/informe-tecnico.html"
msg "  Datos:    $JSON_DIR"

# --- 7) abrir si lo pidió ----------------------------------------------------
if [ "$ABRIR" -eq 1 ] && existe xdg-open; then
  xdg-open "$CLIENTE" >/dev/null 2>&1 &
  xdg-open "$SALIDA/informe-tecnico.html" >/dev/null 2>&1 &
fi

exit "$RC"
