#!/bin/bash
echo "╔═══════════════════════════════════════════╗"
echo "║   CWS UPDATER                            ║"
echo "╚═══════════════════════════════════════════╝"
echo ""
cd ~/CWS
git pull
make clean
make
make install
echo "[+] CWS UPDATED"
cws --version
