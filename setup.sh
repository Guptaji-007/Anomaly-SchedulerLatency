#!/bin/bash
set -e

# setup.sh - Installs all necessary dependencies for Anomaly-SchedulerLatency

echo "=========================================="
echo "    Anomaly-SchedulerLatency Setup"
echo "=========================================="

if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run setup.sh with sudo:"
  echo "    sudo ./setup.sh"
  exit 1
fi

echo "[*] Updating package list..."
apt-get update -y

echo "[*] Installing toolchain and eBPF prerequisites..."
apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    libpcap-dev \
    gcc-multilib \
    build-essential \
    linux-tools-common \
    linux-tools-generic \
    linux-headers-$(uname -r) \
    bpfcc-tools \
    libbpf-dev \
    python3 \
    python3-pip \
    python3-venv \
    git \
    make

echo "[*] Ensuring bpftool is available..."
apt-get install -y linux-tools-$(uname -r) || echo "bpftool already installed or specific version needed."

echo "[*] Installing Python dependencies..."

# Determine the original user to avoid creating root-owned venv
REAL_USER=${SUDO_USER:-$USER}

echo "[*] Creating Python Virtual Environment (venv) as user: $REAL_USER..."
if [ ! -d "venv" ]; then
    sudo -u $REAL_USER python3 -m venv venv
fi

if [ ! -f "requirements.txt" ]; then
    echo -e "numpy\npandas\ntextual\nrich" > requirements.txt
fi

echo "[*] Installing requirements into venv..."
sudo -u $REAL_USER ./venv/bin/pip install -r requirements.txt

echo "=========================================="
echo "[✓] Environment Setup Complete!"
echo "Next step: Run ./build.sh to compile all components."
echo "=========================================="
