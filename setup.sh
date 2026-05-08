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
# Running pip install, ideally in a virtual environment or with --break-system-packages (newer Debian/Ubuntu)
if [ ! -f "requirements.txt" ]; then
    echo "numpy\npandas\ntextual\nrich" > requirements.txt
fi

# Attempt system-wide install or recommend venv
pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt || echo "[!] Please create a python venv: 'python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt'"

echo "=========================================="
echo "[✓] Environment Setup Complete!"
echo "Next step: Run ./build.sh to compile all components."
echo "=========================================="
