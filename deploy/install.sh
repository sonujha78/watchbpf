#!/bin/bash
set -e

echo "=== WatchBPF Installer ==="

# Kernel version check
KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
REQUIRED="5.15"
if [ "$(printf '%s\n' "$REQUIRED" "$KERNEL_VERSION" | sort -V | head -n1)" != "$REQUIRED" ]; then
    echo "WARNING: Kernel $KERNEL_VERSION detected. WatchBPF requires 5.15+."
    echo "Continuing anyway, but eBPF features may not work correctly."
fi

# BTF check
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "ERROR: /sys/kernel/btf/vmlinux not found. Your kernel lacks BTF support."
    echo "WatchBPF requires CO-RE (BTF) support to run."
    exit 1
fi

echo "[1/5] Copying binary to /usr/local/bin/..."
sudo cp bin/watchbpf-agent /usr/local/bin/watchbpf-agent
sudo chmod +x /usr/local/bin/watchbpf-agent

echo "[2/5] Creating config directory..."
sudo mkdir -p /etc/watchbpf

echo "[3/5] Installing systemd service..."
sudo cp deploy/systemd/watchbpf.service /etc/systemd/system/watchbpf.service
sudo systemctl daemon-reload

echo "[4/5] Checking for Gemini API key..."
if [ ! -f /etc/watchbpf/gemini.key ]; then
    echo "No Gemini API key found at /etc/watchbpf/gemini.key"
    echo "WatchBPF will use local Ollama as fallback (if installed)."
    echo "To add a Gemini key later, run:"
    echo "  sudo nano /etc/watchbpf/gemini.key"
    echo "  sudo chmod 600 /etc/watchbpf/gemini.key"
fi

echo "[5/5] Installation complete!"
echo ""
echo "WatchBPF is installed but NOT started yet (dry-run mode by default)."
echo "To start it now:"
echo "  sudo systemctl start watchbpf"
echo "To enable on boot:"
echo "  sudo systemctl enable watchbpf"
echo "To view live logs:"
echo "  sudo journalctl -u watchbpf -f"
echo ""
echo "IMPORTANT: WatchBPF starts in dry-run mode (observe-only, no kill/isolate actions)."
echo "Edit /etc/systemd/system/watchbpf.service and change -enforce=dry-run to"
echo "-enforce=live only after you've reviewed its behavior on your system."
