#!/bin/bash

set -e

function handler() {
    echo ""
    echo "[*] Limpiando hook..."
    make PROG="$PROG" detach-"$MODE"
}

# Parámetros por defecto
IFACE="eth0"
MODE=""
TYPE=""
PROG=""
MAP_NAME="dos_detector"

# Parseo de argumentos
while [[ $# -gt 0 ]]; do
    case "$1" in
        -I|--interface)
            IFACE="$2"
            shift 2
            ;;
        -M|--mode)
            MODE="$2"
            shift 2
            ;;
        --ids)
            TYPE="IDS"
            shift
            ;;
        --ips)
            TYPE="IPS"
            shift
            ;;
        -h|--help)
            echo "Uso: $0 [opciones] <ruta/al/programa>"
            echo "  -I, --interface  Interfaz (default: eth0)"
            echo "  -M, --mode       tc o xdp"
            echo "  --ids            Ejecutar como IDS"
            echo "  --ips            Ejecutar como IPS"
            exit 0
            ;;
        *)
            if [[ -z "$PROG" ]]; then
                PROG="$1"
                shift
            else
                echo "Error: argumento no reconocido '$1'"
                exit 1
            fi
            ;;
    esac
done

# Validación
if [[ -z "$MODE" || -z "$TYPE" || -z "$PROG" ]]; then
    echo "[X] Faltan parámetros. Uso correcto:"
    echo "  $0 --mode tc|xdp --ids|--ips <ruta/al/programa>"
    exit 1
fi

if [[ ! -f "${PROG}.c" ]]; then
    echo "[X] No se encontró el archivo ${PROG}.c"
    exit 1
fi

trap handler SIGINT

echo "[+] Compilando el programa $PROG..."
make PROG="$PROG" MODE="$MODE" TYPE="$TYPE"

echo "[+] Cargando en $IFACE..."
make PROG="$PROG" IFACE="$IFACE" attach-"$MODE" SECTION="$MODE"

echo "[+] Ejecutando el programa en espacio de usuario (Ctrl+C para salir)"
sudo ./main "$MODE" "$MAP_NAME" "$BPF_OBJ" &

wait

echo "[+] Todo limpio. ¡Buen trabajo!"
