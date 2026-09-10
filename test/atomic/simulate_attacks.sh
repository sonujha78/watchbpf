#!/bin/bash
echo "=== WatchBPF Chaos Test Suite ==="
echo "Simulating common attack patterns (all safe, no actual harm)..."

echo "[1] Simulating reverse-shell-like pattern..."
bash -c 'echo "simulated" > /dev/null' 2>/dev/null
sleep 1

echo "[2] Simulating sensitive file access..."
cat /etc/shadow 2>/dev/null
cat /etc/gshadow 2>/dev/null
sleep 1

echo "[3] Simulating port-scan-like behavior..."
for port in 21 22 23 80 443 3389; do
    timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/$port" 2>/dev/null
done
sleep 1

echo "[4] Simulating privilege-check pattern..."
sudo -l 2>/dev/null
sudo -n whoami 2>/dev/null
sleep 1

echo "[5] Simulating suspicious outbound connection..."
curl -s --max-time 2 http://93.184.216.34 -o /dev/null 2>/dev/null

echo "=== Chaos test complete ==="
