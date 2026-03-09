#!/bin/bash
# IPTables Manager - Setup Script
# Run with: sudo bash setup.sh

set -e

echo "🔥 IPTables Manager - Setup"
echo "================================"

# Check root
if [ "$EUID" -ne 0 ]; then
  echo "❌ Please run as root: sudo bash setup.sh"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

# Install system packages
echo "📦 Installing system dependencies..."
apt-get update -q
apt-get install -y -q python3 python3-venv python3-full rsyslog iptables

# Create virtual environment
echo "🐍 Creating Python virtual environment..."
python3 -m venv "$VENV_DIR"
echo "✅ Virtual environment created at $VENV_DIR"

# Install Flask inside venv
echo "📦 Installing Flask into venv..."
"$VENV_DIR/bin/pip" install --quiet flask
echo "✅ Flask installed"

# Create log file
touch /var/log/iptables.log
chmod 644 /var/log/iptables.log
echo "✅ Log file ready: /var/log/iptables.log"

# Setup rsyslog rule
if [ ! -f /etc/rsyslog.d/10-iptables.conf ]; then
  echo "📝 Configuring rsyslog..."
  cat > /etc/rsyslog.d/10-iptables.conf << 'EOF'
:msg, contains, "[IPTABLES" /var/log/iptables.log
& stop
EOF
  systemctl restart rsyslog
  echo "✅ rsyslog configured"
else
  echo "✅ rsyslog already configured"
fi

# Setup logrotate
cat > /etc/logrotate.d/iptables << 'EOF'
/var/log/iptables.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF
echo "✅ logrotate configured"

# Create a convenient run script
cat > "$SCRIPT_DIR/run.sh" << EOF
#!/bin/bash
if [ "\$EUID" -ne 0 ]; then
  echo "❌ Please run as root: sudo bash run.sh"
  exit 1
fi
cd "$SCRIPT_DIR"
echo "🔥 Starting IPTables Manager at http://0.0.0.0:5000"
"$VENV_DIR/bin/python3" app.py
EOF
chmod +x "$SCRIPT_DIR/run.sh"
echo "✅ run.sh created"

# Create systemd service using the venv python
cat > /etc/systemd/system/iptables-manager.service << EOF
[Unit]
Description=IPTables Manager Web UI
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$SCRIPT_DIR
ExecStart=$VENV_DIR/bin/python3 $SCRIPT_DIR/app.py
Restart=always
RestartSec=5
Environment=PATH=$VENV_DIR/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo "✅ Systemd service created"

echo ""
echo "================================"
echo "✅ Setup complete!"
echo ""
echo "▶  Start manually:"
echo "     sudo bash run.sh"
echo ""
echo "▶  Or as a background service:"
echo "     sudo systemctl start iptables-manager"
echo "     sudo systemctl enable iptables-manager   # autostart on boot"
echo "     sudo systemctl status iptables-manager   # check status"
echo ""
echo "▶  Then open browser:"
echo "     http://localhost:5000"
echo "================================"