#!/bin/bash
# Pi Ad Blocker - Install Script
# Run as root: sudo bash install.sh

set -e

echo "🛡️  Pi Ad Blocker - Installer"
echo "=============================="
echo ""

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root: sudo bash install.sh"
    exit 1
fi

# Check for Go
if ! command -v go &> /dev/null; then
    echo "📦 Installing Go..."
    # Detect architecture
    ARCH=$(uname -m)
    case $ARCH in
        aarch64|arm64) GO_ARCH="arm64" ;;
        armv7l|armv6l) GO_ARCH="armv6l" ;;
        x86_64)        GO_ARCH="amd64" ;;
        *)             echo "❌ Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    GO_VERSION="1.21.6"
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz" -O /tmp/go.tar.gz
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    export PATH=$PATH:/usr/local/go/bin

    # Add to profile
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    echo "✅ Go ${GO_VERSION} installed"
fi

echo "📦 Building pi-adblock..."
cd "$(dirname "$0")"
go mod tidy
CGO_ENABLED=0 go build -ldflags="-s -w" -o pi-adblock .
echo "✅ Built successfully"

# Install binary
echo "📁 Installing..."
install -m 755 pi-adblock /usr/local/bin/pi-adblock

# Create config directory
mkdir -p /etc/pi-adblock

# Create default whitelist if it doesn't exist
if [ ! -f /etc/pi-adblock/whitelist.txt ]; then
    cat > /etc/pi-adblock/whitelist.txt << 'EOF'
# Pi Ad Blocker - Whitelist
# Add one domain per line to allow through the blocker.
# Lines starting with # are comments.
#
# Examples:
# ads.example.com
# tracking.example.com
EOF
    echo "✅ Created default whitelist at /etc/pi-adblock/whitelist.txt"
fi

# Create log directory
mkdir -p /var/log
touch /var/log/pi-adblock.log

# Disable systemd-resolved if it's running (it binds to port 53)
if systemctl is-active --quiet systemd-resolved; then
    echo "⚠️  Disabling systemd-resolved (it conflicts with port 53)..."
    systemctl stop systemd-resolved
    systemctl disable systemd-resolved

    # Set a fallback resolv.conf
    echo "nameserver 1.1.1.1" > /etc/resolv.conf
    echo "nameserver 8.8.8.8" >> /etc/resolv.conf
    echo "✅ systemd-resolved disabled"
fi

# Install systemd service
cat > /etc/systemd/system/pi-adblock.service << 'EOF'
[Unit]
Description=Pi Ad Blocker - DNS Sinkhole
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/pi-adblock
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security hardening
ProtectSystem=full
ProtectHome=true
NoNewPrivileges=false
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

echo "✅ Systemd service installed"

# Enable and start
systemctl daemon-reload
systemctl enable pi-adblock
systemctl start pi-adblock

echo ""
echo "============================================"
echo "🎉 Pi Ad Blocker installed and running!"
echo "============================================"
echo ""
echo "  DNS Server:    port 53"
echo "  Web Dashboard: http://$(hostname -I | awk '{print $1}'):8080"
echo ""
echo "📋 Next Steps:"
echo ""
echo "  1. Set your router's DNS to this Pi's IP:"
PI_IP=$(hostname -I | awk '{print $1}')
echo "     → Primary DNS:   $PI_IP"
echo "     → Secondary DNS: 1.1.1.1 (fallback)"
echo ""
echo "  2. Or set individual devices' DNS to: $PI_IP"
echo ""
echo "📝 Useful commands:"
echo "  sudo systemctl status pi-adblock   # Check status"
echo "  sudo systemctl restart pi-adblock  # Restart"
echo "  sudo journalctl -u pi-adblock -f   # View live logs"
echo "  nano /etc/pi-adblock/whitelist.txt  # Edit whitelist"
echo ""echo "Thank you for using Pi Ad Blocker! 🛡️"