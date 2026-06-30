#!/bin/bash
echo "╔═══════════════════════════════════════════╗"
echo "║   CWS ENTERPRISE INSTALLER v2.0          ║"
echo "║   LANGUAGE OF THE STRONG                 ║"
echo "╚═══════════════════════════════════════════╝"
echo ""

if [ -d "$PREFIX" ]; then
    echo "[+] TERMUX DETECTED"
    pkg update -y
    pkg install clang make git openssl libcurl -y
else
    echo "[+] LINUX DETECTED"
    sudo apt update
    sudo apt install build-essential git libssl-dev libcurl4-openssl-dev -y
fi

cd ~
if [ -d "CWS" ]; then
    echo "[+] REMOVING OLD INSTALL..."
    rm -rf CWS
fi

echo "[+] CLONING CWS..."
git clone https://github.com/nyxbappa-sys/CWS.git
cd CWS

echo "[+] BUILDING CWS..."
make clean
make

echo "[+] INSTALLING CWS..."
make install

echo "[+] SETUP COMPLETE"
cws --version
echo ""
echo "╔═══════════════════════════════════════════╗"
echo "║   CWS IS READY FOR THE STRONG            ║"
echo "║   REMEMBER: NO COMMENTS. NO WEAKNESS.    ║"
echo "╚═══════════════════════════════════════════╝"
