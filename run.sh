#!/bin/bash

function handler()
{
    echo ""
    echo "[*] Limpiando hook de tc..."
    make detach
}
set -e

IFACE=eth0

if [ $# -ne 1 ]; then
    echo "[X] Error: introduce el nombre del programa a utilizar!"
    exit 1
else
echo "[+] Compilando el programa $1..."
make PROG=$1

echo "[+] Cargando programa eBPF en $IFACE..."
make PROG=$1 attach

echo "[+] Ejecutando el programa en espacio de usuario (Ctrl+C para salir)"
sudo ./main &

trap handler SIGINT

wait #Soy un genio

echo "[+] Todo limpio. ¡Buen trabajo!"
fi
