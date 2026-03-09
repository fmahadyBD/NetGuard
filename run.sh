#!/bin/bash
if [ "$EUID" -ne 0 ]; then
  echo "❌ Please run as root: sudo bash run.sh"
  exit 1
fi
cd "/home/mahady-hasan-fahim/Desktop/iptables Project"
echo "🔥 Starting IPTables Manager at http://0.0.0.0:5000"
"/home/mahady-hasan-fahim/Desktop/iptables Project/venv/bin/python3" app.py
