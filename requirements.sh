#!/bin/bash

# Verificar root
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: Debes ejecutar como superusuario"
    echo "Ejemplo: sudo ./install.sh"
    exit 1
fi

# Instalar dependencias esenciales
apt update -y && apt install -y \
    nmap \
    python3 \
    python3-pip \
    python3-tk \
    python3-dev \
    tshark \
    net-tools

# Paquetes Python con permisos forzados
python3 -m pip install --break-system-packages \
    python-nmap \
    scapy \
    keyboard \
    netifaces \
    paramiko

# Configurar permisos para sniffing
setcap cap_net_raw+eip $(which python3)